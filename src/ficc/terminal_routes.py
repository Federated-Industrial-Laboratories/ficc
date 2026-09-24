# SPDX-License-Identifier: Apache-2.0
"""Expose scoped terminal intents, one-use tickets and exact session controls."""

from fastapi import Request, WebSocket

from .terminal_schema import TerminalRequest, TerminalStop
from .terminal_stream import stream


def install(app, service, principal, origins, hosts):
    manager = service.terminals

    @app.get("/api/v1/terminals")
    async def terminals(request: Request):
        actor = principal(request, "terminals:read")
        return {"terminals": [manager.view(v) for v in manager.all()
                              if actor.node_ids is None or v["node_id"] in actor.node_ids]}

    @app.post("/api/v1/terminals")
    async def create(body: TerminalRequest, request: Request):
        actor = principal(request, "terminals:execute", body.node_id)
        return await manager.create(body.model_dump(), actor.id)

    @app.get("/api/v1/terminals/{terminal_id}")
    async def detail(terminal_id: str, request: Request):
        value = manager.get(terminal_id)
        principal(request, "terminals:read", value["node_id"])
        return manager.view(value)

    @app.post("/api/v1/terminals/{terminal_id}/tickets")
    async def ticket(terminal_id: str, request: Request):
        actor = principal(request, "terminals:execute")
        return manager.ticket(terminal_id, actor.id)

    @app.post("/api/v1/terminals/{terminal_id}/stop")
    async def stop(terminal_id: str, body: TerminalStop, request: Request):
        actor = principal(request, "terminals:stop")
        return await manager.stop(terminal_id, actor.id)

    @app.post("/api/v1/terminals/{terminal_id}/reconcile")
    async def reconcile(terminal_id: str, request: Request):
        actor = principal(request, "terminals:execute")
        return await manager.reconcile(terminal_id, actor.id)

    @app.websocket("/api/v1/terminals/{terminal_id}/stream")
    async def attach(socket: WebSocket, terminal_id: str):
        await stream(socket, manager, terminal_id, origins, hosts)
