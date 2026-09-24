# SPDX-License-Identifier: Apache-2.0
"""Supervise one nonblocking PTY and its unreaped process group."""

import asyncio
import errno
import fcntl
import os
import signal
import struct
import subprocess
import sys
import termios
import tty
from contextlib import suppress

from .process import ready


class TerminalPTY:
    def __init__(self, args: list[str], cols: int, rows: int):
        self.fd, slave = os.openpty()
        self.process = None
        self.pidfd = None
        try:
            tty.setraw(slave)
            self.resize(cols, rows)
            env = {**os.environ, "TERM": "xterm-256color"}
            self.process = subprocess.Popen([sys.executable, "-m", "ficc.terminal_child", *args],
                                            stdin=slave, stdout=slave, stderr=slave,
                                            start_new_session=True, env=env, close_fds=True)
            self.pidfd = os.pidfd_open(self.process.pid)
            os.set_blocking(self.fd, False)
        except BaseException:
            if self.process is not None:
                with suppress(ProcessLookupError):
                    os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
            os.close(self.fd)
            raise
        finally:
            os.close(slave)

    def resize(self, cols: int, rows: int) -> None:
        if type(cols) is not int or type(rows) is not int or not (2 <= cols <= 300 and 2 <= rows <= 120):
            raise ValueError("Invalid terminal dimensions.")
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    async def read(self, maximum: int = 32768) -> bytes:
        while True:
            try:
                return os.read(self.fd, maximum)
            except BlockingIOError:
                await ready(self.fd)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    return b""
                raise

    async def write(self, data: bytes) -> None:
        offset = 0
        async with asyncio.timeout(5):
            while offset < len(data):
                try:
                    offset += os.write(self.fd, data[offset:])
                except BlockingIOError:
                    await ready(self.fd, writing=True)

    async def close(self) -> None:
        if self.process is None:
            return
        with suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGKILL)
        await asyncio.to_thread(self.process.wait)
        self.process = None
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None
        os.close(self.fd)
