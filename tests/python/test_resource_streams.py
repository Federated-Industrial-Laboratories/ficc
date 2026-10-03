# SPDX-License-Identifier: Apache-2.0
"""Exercise project revocation between a real terminal read and socket delivery."""

import sys

import pytest
from conftest import node
from resource_fixtures import assign
from starlette.websockets import WebSocketDisconnect
from test_identity_projects import member
from test_terminals import request

from ficc.terminal_pty import TerminalPTY


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_terminal_rechecks_project_grant_after_read(console, monkeypatch, count):
    client, service = console
    identities = [f"node-{index}" for index in range(count)]
    for index in range(count):
        service.store.save_node(node(index))
    _, project, actor, headers = member(service, "Terminal operator")
    _, control, _, other = member(service, "Unaffected terminal project")
    assign(client, project, identities)
    assign(client, control, identities)
    received = []
    read = TerminalPTY.read

    async def arguments(value, actor):
        return [sys.executable, "-c", "import os,time;os.write(1,b'PRIVATE OUTPUT');time.sleep(30)"]

    async def read_then_revoke(pty, *args):
        data = await read(pty, *args)
        received.append(data)
        index = len(received)
        service.auth.resources.save(project["id"], identities[index:], [], index)
        return data

    monkeypatch.setattr(service.terminals, "arguments", arguments)
    monkeypatch.setattr(TerminalPTY, "read", read_then_revoke)
    for index in range(count):
        result = client.post("/api/v1/terminals", headers=headers, json=request(index, idempotency_key=f"resource-stream-{index:04}"))
        assert result.status_code == 200
        terminal = result.json()
        ticket = client.post(f"/api/v1/terminals/{terminal['id']}/tickets", headers=headers).json()
        with client.websocket_connect("ws://127.0.0.1:8170" + ticket["websocket_path"]) as socket:
            socket.send_json({"type": "auth", "ticket": ticket["ticket"]})
            assert socket.receive_json()["state"] == "attached"
            assert socket.receive_json()["state"] == "denied"
            with pytest.raises(WebSocketDisconnect):
                socket.receive_bytes()
        assert received[index] == b"PRIVATE OUTPUT"
        assert service.auth.current(actor.id).id == actor.id
        assert service.terminals.get(terminal["id"])["state"] == "interrupted"
        assert not service.terminals.active
        assert client.get("/api/v1/nodes/" + identities[index], headers=headers).status_code == 403
        assert client.get("/api/v1/nodes/" + identities[index], headers=other).status_code == 200
