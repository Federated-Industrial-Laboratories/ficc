# SPDX-License-Identifier: Apache-2.0
"""Verify terminal authority, durable intent and bounded PTY transport."""

import asyncio
import json
import os
import sys

import pytest
from conftest import node
from starlette.websockets import WebSocketDisconnect

from ficc.errors import Failure
from ficc.terminal_pty import TerminalPTY
from ficc.terminal_stream import WINDOW, bridge


def request(index=0, **extra):
    return {"node_id": f"node-{index}", "mode": "ephemeral", "label": "Test shell",
            "cols": 80, "rows": 24, "confirm_execution": True,
            "idempotency_key": "terminal-request-0001", **extra}


def test_intent_scopes_confirmation_and_dedup(console):
    client, service = console
    service.store.save_node(node())
    missing = request()
    missing.pop("confirm_execution")
    assert client.post("/api/v1/terminals", json=missing).status_code == 422
    first = client.post("/api/v1/terminals", json=request()).json()
    again = client.post("/api/v1/terminals", json=request()).json()
    assert first["id"] == again["id"] and first["state"] == "new"
    assert client.post("/api/v1/terminals", json=request(label="Changed")).status_code == 409
    token, _ = service.auth.issue("token", scopes=["terminals:read"])
    assert client.post("/api/v1/terminals", json=request(), headers={"Authorization": "Bearer " + token}).status_code == 403
    assert client.post(f"/api/v1/terminals/{first['id']}/tickets", headers={"Authorization": "Bearer " + token}).status_code == 403
    assert client.post(f"/api/v1/terminals/{first['id']}/stop", json={"confirm_stop": True}).json()["state"] == "stopped"
    assert client.post(f"/api/v1/terminals/{first['id']}/tickets").status_code == 409


@pytest.mark.parametrize("count", [1, 64])
def test_node_grants_and_ticket_replay(console, count):
    client, service = console
    for index in range(count):
        service.store.save_node(node(index))
    for index in range(count):
        token, actor = service.auth.issue("token", scopes=["terminals:execute", "terminals:read", "terminals:stop"],
                                          node_ids=[f"node-{index}"])
        headers = {"Authorization": "Bearer " + token}
        response = client.post("/api/v1/terminals", json=request(index), headers=headers)
        assert response.status_code == 200
        terminal = response.json()
        ticket = client.post(f"/api/v1/terminals/{terminal['id']}/tickets", headers=headers).json()
        assert service.terminals.consume(terminal["id"], ticket["ticket"]) == actor.id
        with pytest.raises(Failure):
            service.terminals.consume(terminal["id"], ticket["ticket"])
        if count > 1:
            denied = client.post("/api/v1/terminals", json=request((index + 1) % count), headers=headers)
            assert denied.status_code == 403
        service.auth.revoke(actor.id)
        with pytest.raises(Failure):
            service.terminals.ticket(terminal["id"], actor.id)
        assert client.post(f"/api/v1/terminals/{terminal['id']}/stop", json={"confirm_stop": True}).status_code == 200


def test_socket_origin_query_and_ticket_guard(console):
    client, service = console
    service.store.save_node(node())
    value = client.post("/api/v1/terminals", json=request()).json()
    path = f"ws://127.0.0.1:8170/api/v1/terminals/{value['id']}/stream"
    for target, origin in [(path, "http://attacker.example"), (path + "?ticket=hidden", "http://127.0.0.1:8170")]:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(target, headers={"Origin": origin}):
                pass
    with client.websocket_connect(path) as socket:
        socket.send_json({"type": "auth", "ticket": "invalid"})
        assert socket.receive_json()["state"] == "denied"
    assert not service.terminals.active


def test_expired_and_wrong_target_tickets(console):
    client, service = console
    service.store.save_node(node())
    value = client.post("/api/v1/terminals", json=request()).json()
    for wrong in (True, False):
        ticket = service.terminals.ticket(value["id"], service.terminals.get(value["id"])["actor"])
        if not wrong:
            for row in service.terminals.tickets.values():
                row["expires_at"] = 0
        with pytest.raises(Failure):
            service.terminals.consume("wrong" if wrong else value["id"], ticket["ticket"])


async def test_real_pty_resize_bytes_and_cleanup():
    code = "import os,termios,fcntl;os.write(1,b'READY');v=os.read(0,4);os.write(1,v+str(os.get_terminal_size()).encode())"
    pty = TerminalPTY([sys.executable, "-c", code], 93, 31)
    pid = pty.process.pid
    try:
        async with asyncio.timeout(5):
            assert await pty.read() == b"READY"
            await pty.write(b"\x00\xffAB")
            output = bytearray()
            while chunk := await pty.read():
                output.extend(chunk)
            assert b"\x00\xffAB" in output and b"columns=93, lines=31" in output
    finally:
        await pty.close()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


class Socket:
    def __init__(self):
        self.messages = asyncio.Queue()
        self.output = bytearray()

    async def receive(self):
        return await self.messages.get()

    async def send_bytes(self, data):
        self.output.extend(data)


async def test_output_window_stops_reads_until_ack():
    socket = Socket()
    pty = TerminalPTY([sys.executable, "-c", "import os,time;os.write(1,b'x'*1048576);time.sleep(10)"], 80, 24)
    task = asyncio.create_task(bridge(socket, pty, lambda: None))
    try:
        async with asyncio.timeout(5):
            while len(socket.output) < WINDOW:
                await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        assert len(socket.output) == WINDOW
        await socket.messages.put({"type": "websocket.receive", "text": json.dumps({"type": "ack", "bytes": 32768})})
        async with asyncio.timeout(5):
            while len(socket.output) < WINDOW + 32768:
                await asyncio.sleep(0.01)
        assert len(socket.output) == WINDOW + 32768
        await socket.messages.put({"type": "websocket.disconnect"})
        assert await task == "detached"
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await pty.close()


@pytest.mark.parametrize("frame", [{"type": "ack", "bytes": 1}, {"type": "resize", "cols": 0, "rows": 24}])
async def test_invalid_controls_refuse(frame):
    socket = Socket()
    pty = TerminalPTY([sys.executable, "-c", "import time;time.sleep(10)"], 80, 24)
    try:
        await socket.messages.put({"type": "websocket.receive", "text": json.dumps(frame)})
        with pytest.raises(ValueError):
            await bridge(socket, pty, lambda: None)
    finally:
        await pty.close()


async def test_active_revocation_is_checked_without_input():
    socket = Socket()
    pty = TerminalPTY([sys.executable, "-c", "import time;time.sleep(10)"], 80, 24)
    def denied():
        raise Failure("denied", "Revoked.", 403)
    try:
        async with asyncio.timeout(3):
            with pytest.raises(Failure, match="Revoked"):
                await bridge(socket, pty, denied)
    finally:
        await pty.close()


def test_authenticated_socket_bytes_revocation_and_no_replay(console, monkeypatch):
    client, service = console
    service.store.save_node(node())
    async def arguments(value, actor):
        return [sys.executable, "-c", "import os;os.write(1,b'READY');os.write(1,os.read(0,100));os.read(0,1)"]
    monkeypatch.setattr(service.terminals, "arguments", arguments)
    terminal = client.post("/api/v1/terminals", json=request()).json()
    ticket = client.post(f"/api/v1/terminals/{terminal['id']}/tickets").json()
    with client.websocket_connect("ws://127.0.0.1:8170" + ticket["websocket_path"]) as socket:
        socket.send_json({"type": "auth", "ticket": ticket["ticket"]})
        assert socket.receive_json()["state"] == "attached"
        assert socket.receive_bytes() == b"READY"
        socket.send_json({"type": "ack", "bytes": 5})
        socket.send_bytes(b"\x00\xffINPUT")
        assert socket.receive_bytes() == b"\x00\xffINPUT"
        actor = service.terminals.get(terminal["id"])["actor"]
        service.auth.revoke(actor)
        assert socket.receive_json()["state"] == "denied"
        with pytest.raises(WebSocketDisconnect):
            socket.receive_bytes()
    assert service.terminals.get(terminal["id"])["state"] == "interrupted"
    assert service.terminals.active == {}


def test_stop_attached_shell_closes_only_owned_process(console, monkeypatch):
    client, service = console
    service.store.save_node(node())
    async def arguments(value, actor):
        return [sys.executable, "-c", "import time;time.sleep(30)"]
    monkeypatch.setattr(service.terminals, "arguments", arguments)
    terminal = client.post("/api/v1/terminals", json=request()).json()
    ticket = client.post(f"/api/v1/terminals/{terminal['id']}/tickets").json()
    with client.websocket_connect("ws://127.0.0.1:8170" + ticket["websocket_path"]) as socket:
        socket.send_json({"type": "auth", "ticket": ticket["ticket"]})
        assert socket.receive_json()["state"] == "attached"
        stopped = client.post(f"/api/v1/terminals/{terminal['id']}/stop", json={"confirm_stop": True})
        assert stopped.status_code == 200 and stopped.json()["state"] == "stopped"
        with pytest.raises(WebSocketDisconnect):
            socket.receive_bytes()
    assert not service.terminals.active


def test_restart_does_not_recreate_ephemeral_intent(console):
    from ficc.terminals import Terminals
    client, service = console
    service.store.save_node(node())
    terminal = client.post("/api/v1/terminals", json=request()).json()
    restarted = Terminals(service)
    assert restarted.get(terminal["id"])["state"] == "interrupted"
    with pytest.raises(Failure):
        restarted.ticket(terminal["id"], service.terminals.get(terminal["id"])["actor"])


def test_schema_two_preserves_existing_credential_grants(tmp_path):
    import sqlite3
    import time

    from ficc.auth import Auth, digest
    from ficc.store import Store

    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    path = directory / "state.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE credentials (id TEXT PRIMARY KEY,digest TEXT UNIQUE NOT NULL,"
                        "kind TEXT NOT NULL,label TEXT NOT NULL,scopes TEXT NOT NULL,nodes TEXT,"
                        "expires REAL NOT NULL,csrf TEXT NOT NULL); PRAGMA user_version=2;")
        db.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?)", (
            "existing", digest("existing-secret"), "token", "Existing", '["jobs:read"]',
            '["node-0"]', time.time() + 60, "csrf"))
    path.chmod(0o600)
    store = Store(path)
    try:
        principal = Auth(store).resolve("existing-secret")
        assert principal.scopes == ["jobs:read"] and principal.node_ids == ["node-0"]
        assert principal.root_ids is None
        with pytest.raises(Failure):
            principal.require("files:read", "node-0", "any-root")
        assert store.db.execute("PRAGMA user_version").fetchone()[0] == 3
    finally:
        store.close()


@pytest.mark.parametrize("remote_state,expected", [("detached", "detached"), ("missing", "exited")])
def test_unknown_tmux_reconciliation_only_queries_saved_identity(console, monkeypatch, remote_state, expected):
    from ficc.terminals import Terminals
    client, service = console
    value = node()
    value["capabilities"]["terminals_tmux"] = True
    service.store.save_node(value)
    calls = []
    async def remote(terminal, action, actor, scope):
        calls.append((terminal["id"], action))
        if action == "create":
            raise Failure("timeout", "The outcome is unknown.", 504)
        return {"state": remote_state}
    monkeypatch.setattr(service.terminals, "remote", remote)
    terminal = client.post("/api/v1/terminals", json=request(mode="tmux")).json()
    assert terminal["state"] == "unknown"
    assert Terminals(service).get(terminal["id"])["state"] == "unknown"
    endpoint = f"/api/v1/terminals/{terminal['id']}/reconcile"
    token, _ = service.auth.issue("token", scopes=["terminals:read"])
    assert client.post(endpoint, headers={"Authorization": "Bearer " + token}).status_code == 403
    assert client.post(endpoint).json()["state"] == expected
    assert calls == [(terminal["id"], "create"), (terminal["id"], "status")]


def test_helper_upgrade_serializes_terminal_and_root_admission(console, monkeypatch, tmp_path):
    from conftest import sample
    client, service = console
    service.store.save_node(node())
    actor = service.auth.resolve(client.cookies.get("ficc_session")).id
    folder = tmp_path / "workspace"
    folder.mkdir()
    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()
        async def install(value, check=None):
            check()
            started.set()
            await release.wait()
        async def probe(value, check=None):
            check()
            result = sample()
            result["helper_version"] = "3"
            return result
        monkeypatch.setattr(service.ssh, "install", install)
        monkeypatch.setattr(service.ssh, "probe", probe)
        upgrade = asyncio.create_task(service.upgrade("node-0", "SHA256:synthetic-key", actor))
        await started.wait()
        terminal = asyncio.create_task(service.terminals.create(request(), actor))
        registration = asyncio.create_task(service.files.register(str(folder), "Workspace"))
        await asyncio.sleep(0.02)
        assert not terminal.done() and not registration.done()
        release.set()
        await upgrade
        assert (await terminal)["state"] == "new"
        assert (await registration)["label"] == "Workspace"
    asyncio.run(scenario())
