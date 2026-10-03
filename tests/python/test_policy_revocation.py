# SPDX-License-Identifier: Apache-2.0
"""Apply real policy changes to queued jobs and an attached operating-system terminal."""

import asyncio
import sys

import pytest
from conftest import node
from policy_fixtures import activate, install_pack
from resource_fixtures import assign
from starlette.websockets import WebSocketDisconnect
from test_identity_projects import member
from test_jobs import Remote
from test_jobs import request as job_request
from test_terminals import request as terminal_request

from ficc.terminal_pty import TerminalPTY


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_policy_revocation_reaches_queued_jobs(policy_console, monkeypatch, count):
    client, service, material = policy_console
    digest = install_pack(client, material)
    remote = Remote()
    monkeypatch.setattr(service.ssh, "job", remote.job)
    for index in range(count):
        service.store.save_node(node(index))
    user, project, actor, headers = member(service, "Queued operator")
    assign(client, project, [f"node-{index}" for index in range(count)])
    service.policies.records.bind(project["id"], user["id"], ["operator"], 0)
    activate(client, digest)
    preview = client.post("/api/v1/operation-previews", headers=headers, json=job_request(count))
    assert preview.status_code == 200, preview.text
    operation = client.post("/api/v1/operations", headers={**headers, "Idempotency-Key": "policy-queue-revocation"},
                            json={"preview_id": preview.json()["preview_id"]})
    assert operation.status_code == 202, operation.text
    service.policies.records.bind(project["id"], user["id"], ["observer"], 1)
    for index in range(count):
        asyncio.run(service.jobs.reconcile(operation.json()["id"], f"node-{index}"))
    saved = service.jobs.store.get(operation.json()["id"])
    assert all(target["state"] == "failed" for target in saved["targets"])
    assert not [call for _, call in remote.calls if call["action"] == "job.submit"]
    assert service.auth.current(actor.id).id == actor.id
    assert client.get("/api/v1/operations/" + saved["id"], headers=headers).status_code == 200


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_policy_revocation_blocks_terminal_output_already_read(policy_console, monkeypatch, count):
    client, service, material = policy_console
    digest = install_pack(client, material)
    service.store.save_node(node())
    user, project, actor, headers = member(service, "Terminal operator")
    assign(client, project, ["node-0"])
    activate(client, digest)
    read = TerminalPTY.read
    seen = []
    async def arguments(value, actor):
        return [sys.executable, "-c", "import os,time;os.write(1,b'PRIVATE POLICY OUTPUT');time.sleep(30)"]
    async def revoke(pty, *args):
        data = await read(pty, *args)
        seen.append(data)
        service.policies.records.bind(project["id"], user["id"], ["observer"], len(seen) * 2 - 1)
        return data
    monkeypatch.setattr(service.terminals, "arguments", arguments)
    monkeypatch.setattr(TerminalPTY, "read", revoke)
    for index in range(count):
        service.policies.records.bind(project["id"], user["id"], ["operator"], index * 2)
        response = client.post("/api/v1/terminals", headers=headers,
                               json=terminal_request(idempotency_key=f"policy-stream-{index:04}"))
        assert response.status_code == 200, response.text
        terminal = response.json()
        ticket = client.post(f"/api/v1/terminals/{terminal['id']}/tickets", headers=headers).json()
        with client.websocket_connect("ws://127.0.0.1:8170" + ticket["websocket_path"]) as socket:
            socket.send_json({"type": "auth", "ticket": ticket["ticket"]})
            assert socket.receive_json()["state"] == "attached"
            assert socket.receive_json()["state"] == "denied"
            with pytest.raises(WebSocketDisconnect):
                socket.receive_bytes()
        assert seen[index] == b"PRIVATE POLICY OUTPUT"
        assert service.terminals.get(terminal["id"])["state"] == "interrupted"
        assert not service.terminals.active
        assert service.auth.current(actor.id).id == actor.id
