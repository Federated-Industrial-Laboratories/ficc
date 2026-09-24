# SPDX-License-Identifier: Apache-2.0
"""Own short-lived observation masters and their private control sockets."""

import asyncio
import os
import select
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from .errors import Failure
from .process import ready
from .settings import MAX_NODES

LIFETIME = 300
PROBE_TIMEOUT = 10
PROBE_RESERVE = PROBE_TIMEOUT + 1
STARTUP = 7
OUTPUT_LIMIT = 16384


def options(args: list[str], **changes: str) -> list[str]:
    result = list(args)
    for index, value in enumerate(args):
        key, separator, _ = value.partition("=")
        if index > 0 and args[index - 1] == "-o" and separator and key in changes:
            result[index] = f"{key}={changes[key]}"
    return result


class StartupFailure(Exception):
    def __init__(self, stderr: bytes):
        self.stderr = stderr


class Master:
    def __init__(self, identity: str, args: list[str]):
        self.identity = identity
        self.directory = Path(tempfile.mkdtemp(prefix="ficc-ssh-"))
        self.socket = self.directory / "control"
        info = self.directory.stat()
        self.directory_identity = (info.st_dev, info.st_ino)
        self.closed = False
        self.expires = time.monotonic() + LIFETIME
        self.stderr = bytearray()
        self.pidfd = -1
        self.process: subprocess.Popen | None = None
        try:
            if len(os.fsencode(self.socket)) > 100:
                raise OSError("The control socket path is too long.")
            command = options(args, ControlPath=str(self.socket), ControlMaster="yes",
                              SessionType="none", StdinNull="yes")
            self.process = subprocess.Popen(
                ["timeout", "--signal=TERM", "--kill-after=2s", f"{LIFETIME}s", *command],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                start_new_session=True, bufsize=0)
            self.pidfd = os.pidfd_open(self.process.pid)
            assert self.process.stderr is not None
            os.set_blocking(self.process.stderr.fileno(), False)
        except OSError as exc:
            if self.process is not None:
                with suppress(ProcessLookupError):
                    os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
                if self.process.stderr is not None:
                    self.process.stderr.close()
            if self.pidfd >= 0:
                os.close(self.pidfd)
            self.directory.rmdir()
            raise Failure("transport_unavailable", "The observation connection could not start.", 503) from exc
        self.reader = asyncio.create_task(self.read())
        self.watcher = asyncio.create_task(self.watch())

    def alive(self) -> bool:
        return (not self.closed and time.monotonic() < self.expires
                and not select.select([self.pidfd], [], [], 0)[0])

    def reusable(self) -> bool:
        return self.alive() and self.expires - time.monotonic() >= PROBE_RESERVE

    def stop(self) -> None:
        if self.closed:
            return
        self.closed = True
        assert self.process is not None
        # The supervisor remains unreaped, so its process group ID cannot be reused.
        with suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGKILL)

    async def read(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        fd = self.process.stderr.fileno()
        while True:
            try:
                data = os.read(fd, 4096)
            except BlockingIOError:
                await ready(fd)
                continue
            if not data:
                return
            room = OUTPUT_LIMIT - len(self.stderr)
            self.stderr.extend(data[:room])
            if len(data) > room:
                self.stop()
                return

    async def watch(self) -> None:
        assert self.process is not None
        try:
            await ready(self.pidfd)
        finally:
            self.stop()
            await asyncio.to_thread(self.process.wait)
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
            assert self.process.stderr is not None
            self.process.stderr.close()
            os.close(self.pidfd)
            self.pidfd = -1
            with suppress(FileNotFoundError):
                self.socket.unlink()
            with suppress(OSError):
                self.directory.rmdir()

    def socket_ready(self) -> bool:
        try:
            directory = self.directory.lstat()
            socket = self.socket.lstat()
        except FileNotFoundError:
            return False
        if ((directory.st_dev, directory.st_ino) != self.directory_identity
                or not stat.S_ISDIR(directory.st_mode) or directory.st_mode & 0o077
                or directory.st_uid != os.getuid() or not stat.S_ISSOCK(socket.st_mode)
                or socket.st_uid != os.getuid()):
            self.stop()
            raise Failure("transport_unavailable", "The observation control socket is invalid.", 503)
        return True

    async def wait_ready(self) -> None:
        async with asyncio.timeout(STARTUP):
            while self.alive():
                if self.socket_ready():
                    return
                await asyncio.sleep(0.02)
        await self.watcher
        raise StartupFailure(bytes(self.stderr))


class Masters:
    def __init__(self):
        self.current: dict[str, Master] = {}
        self.watchers: set[asyncio.Task] = set()
        self.startups = asyncio.Semaphore(16)
        self.closed = False

    def reset(self, node_id: str | None = None) -> None:
        selected = list(self.current) if node_id is None else [node_id]
        for key in selected:
            master = self.current.pop(key, None)
            if master is not None:
                master.stop()

    async def acquire(self, node_id: str, identity: str, args: list[str],
                      check: Callable[[], None] | None = None) -> Master:
        async with self.startups:
            while True:
                if check:
                    check()
                if self.closed:
                    raise Failure("transport_unavailable", "The observation transport is closed.", 503)
                retired = []
                for key, value in list(self.current.items()):
                    if not value.alive() or (key == node_id and (
                        value.identity != identity or not value.reusable()
                    )):
                        self.reset(key)
                        retired.append(value.watcher)
                if not retired:
                    break
                # Reap before admission; cancellation must not cancel ownership cleanup.
                await asyncio.gather(*(asyncio.shield(task) for task in retired))
            return await self.acquire_checked(node_id, identity, args)

    async def acquire_checked(self, node_id: str, identity: str, args: list[str]) -> Master:
        if self.closed:
            raise Failure("transport_unavailable", "The observation transport is closed.", 503)
        master = self.current.get(node_id)
        if master is None:
            if len(self.watchers) >= MAX_NODES:
                raise Failure("capacity", "The observation connection limit was reached.", 409)
            master = Master(identity, args)
            self.current[node_id] = master
            self.watchers.add(master.watcher)
            master.watcher.add_done_callback(self.watchers.discard)
        try:
            await master.wait_ready()
            if not master.reusable():
                raise Failure("unreachable", "The observation connection has insufficient lifetime.", 502)
        except BaseException:
            if self.current.get(node_id) is master:
                self.reset(node_id)
            raise
        return master

    async def close(self) -> None:
        self.closed = True
        self.reset()
        await asyncio.gather(*tuple(self.watchers), return_exceptions=True)
