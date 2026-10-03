# SPDX-License-Identifier: Apache-2.0
"""Call the local supervisor through a bounded authenticated Unix socket exchange."""

import asyncio
import socket
import struct

from .protocol import MAX_MESSAGE, MESSAGE
from .spec import encoded
from .wire import MAX_REPLY, decode


def credentials(connection):
    pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return pid, uid, gid


async def receive(reader, maximum):
    length = struct.unpack("!I", await reader.readexactly(4))[0]
    if not 0 < length <= maximum:
        raise ValueError("The local executor frame exceeds its declared bound.")
    return await reader.readexactly(length)


async def send(writer, data, maximum):
    if not 0 < len(data) <= maximum:
        raise ValueError("The local executor frame exceeds its declared bound.")
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()


class Client:
    def __init__(self, socket_path, *, timeout=10):
        self.socket_path, self.timeout = str(socket_path), timeout

    async def request(self, message):
        request = MESSAGE.validate_json(message.model_dump_json())
        async with asyncio.timeout(self.timeout):
            reader, writer = await asyncio.open_unix_connection(self.socket_path, limit=MAX_REPLY + 4)
            try:
                if credentials(writer.get_extra_info("socket"))[1] != 0:
                    raise ValueError("The local executor socket is not served by the machine administrator.")
                await send(writer, encoded(request.model_dump()), MAX_MESSAGE)
                reply = decode(await receive(reader, MAX_REPLY))
                if reply.version != request.version or reply.id != request.id:
                    raise ValueError("The local executor reply belongs to another request.")
                return reply.model_dump()
            except asyncio.IncompleteReadError as exc:
                raise OSError("The local executor disconnected before completing its reply.") from exc
            finally:
                writer.close()
                await writer.wait_closed()
