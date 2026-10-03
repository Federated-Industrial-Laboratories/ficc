# SPDX-License-Identifier: Apache-2.0
"""Attach host-owned viewers after exact-origin and single-use ticket checks."""

import asyncio
import json
from contextlib import suppress

from fastapi import Request, WebSocket
from starlette.websockets import WebSocketDisconnect

from .errors import Failure
from .ssh import SSH
from .viewer_stream import bridge


def install(app, service, principal, origins, hosts):
    manager = service.viewers

    @app.post("/api/v1/viewers/{reference}/tickets")
    async def ticket(reference: str, request: Request):
        actor = principal(request, "vm:console")
        return manager.ticket(reference, actor.id)

    @app.websocket("/api/v1/viewers/{reference}/stream")
    async def stream(socket: WebSocket, reference: str):
        await asyncio.create_task(attach(socket, reference))

    async def attach(socket, reference):
        if (socket.headers.get("host") not in hosts or socket.headers.get("origin") not in origins
                or socket.headers.get("sec-fetch-site") == "cross-site" or socket.url.query):
            await socket.close(code=1008)
            return
        await socket.accept()
        actor, owned = None, False
        arguments = None
        try:
            async with asyncio.timeout(5):
                text = await socket.receive_text()
                if len(text) > 512:
                    raise ValueError("Invalid display ticket frame.")
                value = json.loads(text)
                if not isinstance(value, dict) or set(value) != {"type", "ticket"} or value["type"] != "auth":
                    raise ValueError("Invalid display ticket frame.")
                actor = manager.consume(reference, value["ticket"])
                owned = True
            current = manager.current(reference, actor)

            def check():
                manager.current(reference, actor)

            host = service.vm_providers.adapter(current["descriptor"].get("provider", "libvirt"))
            descriptor = current["descriptor"]
            graphics = descriptor["graphics"]
            if graphics.get("protocol", "vnc") == "rdp":
                connect = getattr(host, "console_connection", None)
                if connect is None:
                    raise Failure("viewer_unavailable", "The provider has no compatible display transport.", 409)
                connection = await connect(descriptor, check)
                check()
                service.store.audit("viewer.attach", descriptor["vm_id"], actor=actor)
                await bridge(socket, service.settings.viewer_runtime, [], b"", check, connection=connection)
            elif graphics.get("protocol", "vnc") == "vnc":
                arguments, header = await host.console_command(descriptor, check)
                trust = SSH.connection_check(arguments)
                def transport_check():
                    check()
                    trust()
                transport_check()
                service.store.audit("viewer.attach", descriptor["vm_id"], actor=actor)
                await bridge(socket, service.settings.viewer_runtime, arguments, header, transport_check,
                             authentication=graphics.get("authentication", "none"))
            else:
                raise Failure("viewer_unavailable", "The provider has no compatible display protocol.", 409)
        except Failure as exc:
            with suppress(WebSocketDisconnect, RuntimeError):
                await socket.send_json({"type": "error", "code": exc.code, "message": exc.message})
        except (ValueError, OSError, EOFError, UnicodeError, TimeoutError, WebSocketDisconnect):
            with suppress(WebSocketDisconnect, RuntimeError):
                await socket.send_json({"type": "error", "message": "The display connection closed. Request a new connection."})
        finally:
            if arguments is not None:
                SSH.release(arguments)
            if owned:
                manager.active.pop(reference, None)
                manager.references.pop(reference, None)
                service.store.audit("viewer.detach", reference, actor=actor)
            with suppress(WebSocketDisconnect, RuntimeError):
                await socket.close()
