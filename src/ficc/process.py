# SPDX-License-Identifier: Apache-2.0
"""Run child processes with finite output, time, and process lifetimes."""

import asyncio
import os
import signal
import subprocess

from .errors import Failure
from .settings import MAX_MESSAGE


async def ready(fd: int, writing: bool = False) -> None:
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def notify() -> None:
        if not future.done():
            future.set_result(None)

    add = loop.add_writer if writing else loop.add_reader
    remove = loop.remove_writer if writing else loop.remove_reader
    add(fd, notify)
    try:
        await future
    finally:
        remove(fd)


async def run(command: list[str], payload: bytes = b"", timeout: float = 10,
              maximum: int = MAX_MESSAGE) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    except OSError as exc:
        raise Failure("transport_unavailable", "The required program is unavailable.", 503) from exc
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    pipes = (process.stdin, process.stdout, process.stderr)
    tasks: list[asyncio.Task] = []
    pidfd = None

    async def read(fd: int) -> bytes:
        result = bytearray()
        while True:
            try:
                chunk = os.read(fd, 8192)
            except BlockingIOError:
                await ready(fd)
                continue
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > maximum:
                raise Failure("output_limit", "The remote response exceeds the limit.", 502)

    async def write(fd: int) -> None:
        offset = 0
        try:
            while offset < len(payload):
                try:
                    offset += os.write(fd, payload[offset:offset + 8192])
                except BlockingIOError:
                    await ready(fd, writing=True)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            pipes[0].close()

    try:
        pidfd = os.pidfd_open(process.pid)
        for pipe in pipes:
            os.set_blocking(pipe.fileno(), False)
        stdout_task = asyncio.create_task(read(pipes[1].fileno()))
        stderr_task = asyncio.create_task(read(pipes[2].fileno()))
        tasks = [stdout_task, stderr_task, asyncio.create_task(write(pipes[0].fileno())),
                 asyncio.create_task(ready(pidfd))]
        async with asyncio.timeout(timeout):
            await asyncio.gather(*tasks)
            stdout, stderr = stdout_task.result(), stderr_task.result()
    except TimeoutError as exc:
        raise Failure("unreachable", "The connection timed out.", 502) from exc
    except OSError as exc:
        raise Failure("transport_unavailable", "The process could not be supervised.", 503) from exc
    finally:
        # Keep the direct child unreaped until the owned group is killed. Its PID
        # cannot be reused, even when it exits before a descendant closes a pipe.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        code = await asyncio.to_thread(process.wait)
        for pipe in pipes:
            pipe.close()
        if pidfd is not None:
            os.close(pidfd)
    return code, stdout, stderr
