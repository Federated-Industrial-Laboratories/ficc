# SPDX-License-Identifier: Apache-2.0
"""Use the maintained HyperNet SDK; no address, TLS or route fallback exists here."""
import asyncio
import importlib
import json
import struct

from ..errors import Failure
from .identity import encode
from .schema import PROTOCOL

FRAME = 1024*1024


class Channel:
    def __init__(self, stream, reader, writer):
        self.stream, self.reader, self.writer = stream, reader, writer
        self.peer = stream.peer

    @classmethod
    async def wrap(cls, stream):
        stream.socket.setblocking(False)
        try:
            reader, writer = await asyncio.open_connection(sock=stream.socket, limit=FRAME+4)
        except BaseException:
            stream.close()
            raise
        return cls(stream, reader, writer)

    async def send(self, data):
        if len(data) > FRAME:
            raise Failure("federation_frame", "The federation frame exceeds 1 MiB.", 413)
        self.writer.write(struct.pack("!I", len(data)))
        self.writer.write(data)
        await self.writer.drain()

    async def receive(self):
        size, = struct.unpack("!I", await self.reader.readexactly(4))
        if size > FRAME:
            raise Failure("federation_frame", "The remote federation frame exceeds 1 MiB.", 502)
        return await self.reader.readexactly(size)

    async def send_json(self, value):
        await self.send(encode(value))

    async def json(self):
        try:
            value = json.loads(await self.receive())
            if not isinstance(value, dict):
                raise ValueError("Expected an object.")
            return value
        except (ValueError, UnicodeError):
            raise Failure("federation_protocol", "The peer returned an invalid federation message.", 502) from None

    async def close(self):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (OSError, ConnectionError):
            pass
        self.stream.close()


class HyperNet:
    def __init__(self, directory):
        try:
            module = importlib.import_module("hypernet_streams")
        except ImportError:
            raise Failure("hypernet_sdk_missing", "Install HyperNetSuite's Python application-stream SDK in this FICC environment.", 409) from None
        self.agent = module.Agent(directory)

    async def status(self):
        try:
            return await asyncio.to_thread(self.agent.status)
        except (OSError, RuntimeError) as exc:
            raise Failure("hypernet_unavailable", "The configured HyperNet companion is unavailable.", 503) from exc

    async def connect(self, service):
        try:
            pending = asyncio.create_task(asyncio.to_thread(self.agent.connect, service, protocol=PROTOCOL, timeout=30))
            try:
                stream = await asyncio.shield(pending)
            except asyncio.CancelledError:
                # Threaded SDK calls are finite but cannot be killed. Close a
                # late successful socket instead of leaking an admitted stream.
                pending.add_done_callback(self._close_late)
                raise
            return await Channel.wrap(stream)
        except (OSError, RuntimeError) as exc:
            detail = " ".join(str(exc).split())[:512]
            raise Failure("hypernet_connect", "HyperNet could not establish the authenticated application stream: " + detail, 503) from exc

    async def accept(self):
        pending = asyncio.create_task(asyncio.to_thread(self.agent.accept, timeout=1))
        try:
            stream = await asyncio.shield(pending)
        except asyncio.CancelledError:
            pending.add_done_callback(self._close_late)
            raise
        return await Channel.wrap(stream)

    @staticmethod
    def _close_late(task):
        try:
            task.result().close()
        except (OSError, RuntimeError, asyncio.CancelledError):
            pass
