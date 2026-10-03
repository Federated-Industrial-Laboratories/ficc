# SPDX-License-Identifier: Apache-2.0
"""Read bounded real native display frames and return protocol acknowledgements."""

import asyncio
import base64
import contextlib
import hashlib
import json

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from ficc.viewer import wire

from .workflows import request


async def input_event(socket, *values):
    await socket.send(json.dumps({"type": "input", "instruction": wire.instruction(*values).decode("ascii")}))


def instructions(packet):
    """Read complete length-prefixed elements without the host output validator."""
    assert isinstance(packet, bytes) and 0 < len(packet) <= 65536
    text = packet.decode("ascii")
    position, values, result = 0, [], []
    while position < len(text):
        dot = text.find(".", position, position + 7)
        assert dot > position and text[position:dot].isdigit()
        end = dot + 1 + int(text[position:dot])
        assert end < len(text) and len(values) < 128
        values.append(text[dot + 1:end])
        delimiter = text[end]
        assert delimiter in {",", ";"}
        position = end + 1
        if delimiter == ";":
            result.append(tuple(values))
            values = []
            assert len(result) <= 64
    assert result and not values
    return result


class Reader:
    """Acknowledge each frame while retaining only its digest and sequence."""

    def __init__(self, socket):
        self.socket = socket
        self.changed = asyncio.Event()
        self.sequence = self.consumed = 0
        self.digest = self.failure = None
        self.operations = {}
        self.task = asyncio.create_task(self.receive())

    async def send(self, value):
        if self.failure:
            raise self.failure
        await self.socket.send(value)

    async def receive(self):
        images, total = bytearray(), 0
        try:
            while True:
                packet = await self.socket.recv()
                if isinstance(packet, str):
                    error = json.loads(packet)
                    assert error["type"] == "error"
                    code = str(error.get("code", "closed"))[:80]
                    message = str(error.get("message", ""))[:240]
                    raise AssertionError(f"The real display failed: {code}: {message}")
                total += len(packet)
                assert total < 4 * 1024 * 1024
                decoded = instructions(packet)
                await self.send(json.dumps({"type": "ack", "bytes": len(packet)}))
                for values in decoded:
                    self.operations[values[0]] = self.operations.get(values[0], 0) + 1
                    if values[0] == "blob":
                        images.extend(base64.b64decode(values[2], validate=True))
                        await input_event(self, "ack", int(values[1]), "OK", 0)
                    if values[0] == "sync":
                        await input_event(self, "sync", int(values[1]))
                        if images:
                            assert b"\x89PNG\r\n\x1a\n" in images
                            self.digest = hashlib.sha256(images).hexdigest()
                            self.sequence += 1
                            images.clear()
                            self.changed.set()
                        total = 0
        except (AssertionError, ConnectionClosed, ValueError) as exc:
            self.failure = exc
        finally:
            self.changed.set()

    async def wait_closed(self):
        await self.socket.wait_closed()
        await self.task

    async def close(self):
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)


async def frame(reader):
    try:
        async with asyncio.timeout(20):
            while True:
                if reader.failure:
                    raise reader.failure
                if reader.sequence > reader.consumed:
                    reader.consumed = reader.sequence
                    return reader.digest
                reader.changed.clear()
                await reader.changed.wait()
    except TimeoutError:
        raise AssertionError(f"The display frame timed out: {reader.operations}.") from None


@contextlib.asynccontextmanager
async def display(lab, client, reference):
    ticket = await request(client, "POST", f"/api/v1/viewers/{reference}/tickets")
    url = lab.origin.replace("https://", "wss://") + f"/api/v1/viewers/{reference}/stream"
    async with connect(url, ssl=lab.tls, origin=lab.origin, proxy=None, compression=None,
                       open_timeout=10, close_timeout=3, max_size=65536) as socket:
        await socket.send(json.dumps({"type": "auth", "ticket": ticket["ticket"]}))
        reader = Reader(socket)
        try:
            initial = await frame(reader)
            yield reader, ticket, initial
        finally:
            await reader.close()
