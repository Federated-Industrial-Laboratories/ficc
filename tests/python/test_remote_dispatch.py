# SPDX-License-Identifier: Apache-2.0
"""Recheck external authority before queued commands and already-read terminal output."""

import asyncio
import sys
import time

import pytest
from conftest import node
from remote_fixtures import ISSUER, ORIGIN, external_session, login, session_headers
from starlette.websockets import WebSocketDisconnect
from test_identity_projects import member
from test_jobs import Remote
from test_jobs import request as job_request
from test_terminals import request as terminal_request

from ficc.terminal_pty import TerminalPTY


def operator(client, service, provider):
    user, project, _, _ = member(service, "Remote command operator")
    service.remote_auth.records.save(ISSUER, "operator", user["id"], False, 0)
    assert login(client, provider, "operator").headers["location"] == "/"
    session = client.get("/api/v1/session").json()
    return user, project, session["principal"]["id"], {"X-CSRF-Token": session["csrf"]}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_expired_external_authority_blocks_queued_commands(remote_console, monkeypatch, count):
    client, service, provider, _ = remote_console
    _, project, actor, headers = operator(client, service, provider)
    remote = Remote()
    monkeypatch.setattr(service.ssh, "job", remote.job)
    for index in range(count):
        service.store.save_node(node(index))
    service.auth.resources.save(project["id"], [f"node-{index}" for index in range(count)], [], 0)
    preview = client.post("/api/v1/operation-previews", headers=headers, json=job_request(count))
    assert preview.status_code == 200, preview.text
    operation = client.post("/api/v1/operations", headers={**headers, "Idempotency-Key": "remote-lease-expiry"},
                            json={"preview_id": preview.json()["preview_id"]})
    assert operation.status_code == 202, operation.text
    service.remote_auth.bindings[actor]["assertion"]["valid_until"] = time.time() - 1
    for index in range(count):
        asyncio.run(service.jobs.reconcile(operation.json()["id"], f"node-{index}"))
    saved = service.jobs.store.get(operation.json()["id"])
    assert all(target["state"] == "failed" for target in saved["targets"])
    assert not [call for _, call in remote.calls if call["action"] == "job.submit"]


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_remote_terminal_stops_after_mapping_revocation(remote_console, monkeypatch, count):
    client, service, provider, gateway = remote_console
    service.store.save_node(node())
    records, subjects, payloads = [], {}, {}
    for index in range(count + 1):
        user, project, _, _ = member(service, f"Stream operator {index}")
        subject = f"stream-{index}"
        service.remote_auth.records.save(ISSUER, subject, user["id"], False, 0)
        service.auth.resources.save(project["id"], ["node-0"], [], 0)
        secret, principal = asyncio.run(external_session(service, provider, subject))
        payload = f"PRIVATE REMOTE OUTPUT {index}".encode()
        records.append((user, principal, session_headers(secret, principal, index)))
        subjects[payload] = (subject, user["id"])
        payloads[user["id"]] = payload
    control_user, control_principal, control_headers = records[-1]
    read, seen = TerminalPTY.read, []

    async def arguments(value, actor):
        if value["subject_id"] == control_user["id"]:
            code = ("import os,tty,time;tty.setraw(0);os.write(1,b'CONTROL READY');"
                    "data=os.read(0,1);os.write(1,b'CONTROL '+data);time.sleep(30)")
        else:
            code = f"import os,time;os.write(1,{payloads[value['subject_id']]!r});time.sleep(30)"
        return [sys.executable, "-c", code]

    async def revoke(pty, *args):
        data = await read(pty, *args)
        if data in subjects:
            seen.append(data)
            subject, user_id = subjects[data]
            service.remote_auth.records.save(ISSUER, subject, user_id, True, 1)
        return data

    def terminal(headers, index):
        response = client.post("/api/v1/terminals", headers=headers,
                               json=terminal_request(idempotency_key=f"remote-stream-revoke-{index}"))
        assert response.status_code == 200, response.text
        value = response.json()
        ticket = client.post(f"/api/v1/terminals/{value['id']}/tickets", headers=headers)
        assert ticket.status_code == 200, ticket.text
        return value, ticket.json()

    monkeypatch.setattr(service.terminals, "arguments", arguments)
    monkeypatch.setattr(TerminalPTY, "read", revoke)
    control_terminal, control_ticket = terminal(control_headers, count)
    with client.websocket_connect(ORIGIN.replace("https", "wss") + control_ticket["websocket_path"],
                                  headers={**gateway, **control_headers}) as control:
        control.send_json({"type": "auth", "ticket": control_ticket["ticket"]})
        assert control.receive_json()["state"] == "attached"
        assert control.receive_bytes() == b"CONTROL READY"
        control.send_json({"type": "ack", "bytes": len(b"CONTROL READY")})
        for index, (user, _, headers) in enumerate(records[:-1]):
            value, ticket = terminal(headers, index)
            with client.websocket_connect(ORIGIN.replace("https", "wss") + ticket["websocket_path"],
                                          headers={**gateway, **headers}) as socket:
                socket.send_json({"type": "auth", "ticket": ticket["ticket"]})
                assert socket.receive_json()["state"] == "attached"
                assert socket.receive_json()["state"] == "denied"
                with pytest.raises(WebSocketDisconnect):
                    socket.receive_bytes()
            assert seen[-1] == payloads[user["id"]]
            assert service.terminals.get(value["id"])["state"] == "interrupted"
            assert set(service.terminals.active) == {control_terminal["id"]}
            assert service.auth.current(control_principal.id).subject_id == control_user["id"]
        assert seen == [payloads[user["id"]] for user, _, _ in records[:-1]]
        control.send_bytes(b"Q")
        assert control.receive_bytes() == b"CONTROL Q"
        control.send_json({"type": "ack", "bytes": len(b"CONTROL Q")})
    assert not service.terminals.active
