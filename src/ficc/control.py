# SPDX-License-Identifier: Apache-2.0
"""Issue local credentials through a private socket with peer identity checks."""

import asyncio
import fcntl
import json
import os
import socket
import struct
from contextlib import suppress

from .errors import Failure
from .service import Service


class Control:
    def __init__(self, service: Service):
        self.service = service
        self.server: asyncio.AbstractServer | None = None
        self.lock_fd: int | None = None
        self.clients: set[asyncio.Task] = set()

    async def start(self) -> None:
        path = self.service.settings.socket_path
        self.lock_fd = os.open(path.parent / "service.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise ValueError("A service already uses this state directory.") from None
        if path.exists() or path.is_symlink():
            path.unlink()
        self.server = await asyncio.start_unix_server(self.handle, path=str(path), limit=8193)
        os.chmod(path, 0o600)

    async def close(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            with suppress(FileNotFoundError):
                self.service.settings.socket_path.unlink()
        for task in self.clients:
            task.cancel()
        await asyncio.gather(*self.clients, return_exceptions=True)
        if self.lock_fd is not None:
            os.close(self.lock_fd)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self.clients.add(task)
        try:
            peer = writer.get_extra_info("socket").getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            if struct.unpack("3i", peer)[1] != os.getuid() or len(self.clients) > 16:
                return
            async with asyncio.timeout(3):
                data = await reader.readline()
                if len(data) > 8192:
                    return
                request = json.loads(data)
                action = request.get("action")
                auth = self.service.auth
                if action == "bootstrap":
                    secret, principal = auth.issue("bootstrap", lifetime=60)
                elif action == "job-credential":
                    secret, principal = auth.issue("token", "Local job CLI", lifetime=3600)
                    self.service.store.audit("credential.create", principal.id)
                elif action == "ephemeral":
                    secret, principal = auth.issue("token", "Local CLI", lifetime=60)
                elif action == "token":
                    secret, principal = auth.issue(
                        "token", label=request["label"], scopes=request["scopes"],
                        node_ids=request.get("node_ids"), lifetime=request.get("lifetime", 3600))
                    self.service.store.audit("credential.create", principal.id)
                elif action == "revoke":
                    auth.revoke(request["id"])
                    writer.write(b'{"ok":true}\n')
                    await writer.drain()
                    return
                else:
                    raise Failure("invalid_action", "The local action is not supported.")
                response = {"credential": secret, "id": principal.id,
                            "origin": self.service.settings.origin, "expires_at": principal.expires_at}
                writer.write(json.dumps(response).encode() + b"\n")
                await writer.drain()
        except (KeyError, ValueError, TypeError, TimeoutError, Failure):
            with suppress(ConnectionError):
                writer.write(b'{"error":"local_request_failed"}\n')
                await writer.drain()
        finally:
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()
            self.clients.discard(task)
