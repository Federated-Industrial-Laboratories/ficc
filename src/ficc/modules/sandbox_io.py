# SPDX-License-Identifier: Apache-2.0
"""Exchange bounded sequential frames over already-isolated inherited pipes."""

import asyncio
import os
import struct

from ..errors import Failure
from ..pipe_ready import ready
from .protocol import MAX_OUTPUT
from .validation import MAX_JSON, invalid, loads


class Channel:
    def __init__(self, stdin, stdout, initial_bytes: int, cancel: bytes):
        self.stdin, self.stdout = stdin, stdout
        self.received, self.sent = 0, initial_bytes
        self.cancel = cancel

    def idle(self) -> None:
        try:
            value = os.read(self.stdout.fileno(), 1)
        except BlockingIOError:
            return
        if value:
            raise invalid("The module sent pipelined broker traffic.")
        raise invalid("The module closed its output during a broker call.")

    async def exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            try:
                chunk = os.read(self.stdout.fileno(), size - len(data))
            except BlockingIOError:
                await ready(self.stdout.fileno())
                continue
            if not chunk:
                raise invalid("The module returned an incomplete frame.")
            self.received += len(chunk)
            if self.received > MAX_OUTPUT:
                raise Failure("module_output_limit", "The module output exceeds its limit.", 502)
            data.extend(chunk)
        return bytes(data)

    async def receive(self) -> dict:
        size = struct.unpack(">I", await self.exact(4))[0]
        if not 0 < size <= MAX_JSON:
            raise invalid("The module frame size is invalid.")
        result = loads(await self.exact(size))
        if not isinstance(result, dict):
            raise invalid("A module frame must contain an object.")
        return result

    async def dispatch(self, operation):
        task = asyncio.create_task(operation)
        monitor = asyncio.create_task(ready(self.stdout.fileno()))
        try:
            self.idle()
            await asyncio.wait((task, monitor), return_when=asyncio.FIRST_COMPLETED)
            self.idle()
            return await task
        finally:
            monitor.cancel()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, monitor, return_exceptions=True)

    async def send(self, data: bytes) -> None:
        self.sent += len(data)
        if self.sent > MAX_OUTPUT:
            raise Failure("module_output_limit", "The broker response exceeds its limit.", 502)
        offset = 0
        while offset < len(data):
            self.idle()
            try:
                offset += os.write(self.stdin.fileno(), data[offset:offset + 8192])
            except BlockingIOError:
                await ready(self.stdin.fileno(), writing=True)

    async def complete(self) -> None:
        self.stdin.close()
        while True:
            try:
                extra = os.read(self.stdout.fileno(), 1)
            except BlockingIOError:
                await ready(self.stdout.fileno())
                continue
            if extra:
                raise invalid("The module returned traffic after its final result.")
            return

    def cancel_nowait(self) -> None:
        """Make one bounded nonblocking write; cooperation is never required."""
        if not self.stdin.closed:
            try:
                os.write(self.stdin.fileno(), self.cancel)
            except OSError:
                pass
