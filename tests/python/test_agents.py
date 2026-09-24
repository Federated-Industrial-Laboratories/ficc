# SPDX-License-Identifier: Apache-2.0
"""Exercise explicit agent launch, authority, identity and message receipts."""

import asyncio

import pytest
from conftest import node

from ficc.errors import Failure


@pytest.fixture
def agents(console, monkeypatch, tmp_path):
    client, service = console
    remote = {}
    calls = []
    async def request(node_id, action, body, check=None):
        if check:
            check()
        calls.append((node_id, action, body))
        if action == "probe":
            return {**body["profile"], "version": "unversioned", "delivery_method": "inbox"}
        identity = body["agent_id"]
        if action == "launch":
            remote[identity] = {"state": "ready", "runtime_session_id": identity,
                                "last_contact": 1000, "items": {}, "outbox": []}
        value = remote[identity]
        if action == "stop":
            value["state"] = "stopped"
        result = {key: value[key] for key in ("state", "runtime_session_id", "last_contact")}
        if action == "exchange":
            for item in body["deliveries"]:
                value["items"].setdefault(item["id"], item)
            result["receipts"] = [{"id": key, "state": "tool-read" if key in value["items"] else "missing", "detail": "Observed fixture read"}
                                   for key in body["receipt_ids"]]
            result["outbox"] = value["outbox"]
            value["outbox"] = [v for v in value["outbox"] if v["id"] not in body["outbox_acks"]]
        return result
    monkeypatch.setattr(service.agents, "remote", request)
    def setup(index=0, run=None):
        value = node(index)
        value.update(helper_version="3", capabilities={"terminals_tmux": True, "agents": True})
        service.store.save_node(value)
        profile = asyncio.run(service.agents.register({"node_id": value["id"], "name": "Fixture", "adapter": "generic",
                                                       "argv": ["/bin/sh"], "workspace": str(tmp_path)}))
        if run is None:
            response = client.post("/api/v1/bus/runs", json={"name": "fixture", "idempotency_key": "run-fixture-" + str(index).zfill(16)})
            assert response.status_code == 200, response.text
            run = response.json()
        preview = client.post("/api/v1/agent-previews", json={"profile_id": profile["id"], "label": "Fixture agent", "run_id": run["id"]})
        assert preview.status_code == 200, preview.text
        request = {"preview_id": preview.json()["preview_id"], "idempotency_key": "launch-fixture-" + str(index).zfill(16), "confirm_execution": True}
        response = client.post("/api/v1/agents", json=request)
        assert response.status_code == 200, response.text
        return profile, run, response.json(), request
    return client, service, remote, calls, setup


def message(identity, **extra):
    return {"type": "note", "body": {"text": "A bounded observation; $(touch /tmp/not-executed)"},
            "recipient_ids": [identity], "delivery": "inbox", "reply_to": None,
            "idempotency_key": "message-request-00001", "confirm_delivery": True, **extra}


@pytest.mark.parametrize("count", [1, 64])
def test_launch_delivery_stop_and_retained_identity(agents, count):
    client, service, remote, calls, setup = agents
    identifiers = set()
    for index in range(count):
        profile, run, agent, intent = setup(index)
        identifiers.add(agent["id"])
        assert agent["state"] == "ready"
        assert client.post("/api/v1/agents", json=intent).json()["id"] == agent["id"]
        terminal = service.terminals.get(agent["terminal_id"])
        assert terminal["agent_id"] == agent["id"] and terminal["state"] == "detached"
        response = client.post(f'/api/v1/bus/runs/{run["id"]}/messages', json=message(agent["id"], idempotency_key=f"message-{index:020d}"))
        assert response.status_code == 200, response.text
        saved = response.json()
        assert saved["deliveries"][0]["state"] == "host-stored"
        async def exchange():
            await service.agents.exchange(service.agents.store.get("agents", agent["id"]))
            await service.agents.exchange(service.agents.store.get("agents", agent["id"]))
        asyncio.run(exchange())
        delivery = service.agents.store.get("bus_deliveries", saved["deliveries"][0]["id"])
        assert delivery["state"] == "tool-read"
        assert remote[agent["id"]]["items"][delivery["id"]]["agent_id"] == agent["id"]
        assert client.post(f'/api/v1/agents/{agent["id"]}/stop', json={"confirm_stop": True}).json()["state"] == "stopped"
        assert client.post(f'/api/v1/bus/runs/{run["id"]}/close', json={"confirm_close": True}).json()["state"] == "closed"
        assert service.retained_history(agent["node_id"])
    assert len(identifiers) == count
    assert sum(action == "launch" for _, action, _ in calls) == count


def test_scope_restrictions_and_same_run_routing(agents):
    client, service, _, _, setup = agents
    _, run, agent, intent = setup()
    _, other_run, other, _ = setup(1)
    token, _ = service.auth.issue("token", scopes=["agents:read", "bus:read"], node_ids=[agent["node_id"]])
    headers = {"Authorization": "Bearer " + token}
    assert [v["id"] for v in client.get("/api/v1/agents", headers=headers).json()["agents"]] == [agent["id"]]
    assert client.get(f'/api/v1/agents/{other["id"]}', headers=headers).status_code == 403
    assert client.post("/api/v1/agents", json=intent, headers=headers).status_code == 403
    assert client.post(f'/api/v1/agents/{agent["id"]}/stop', json={"confirm_stop": True}, headers=headers).status_code == 403
    assert client.get(f'/api/v1/bus/runs/{other_run["id"]}/messages', headers=headers).status_code == 403
    assert client.post(f'/api/v1/bus/runs/{run["id"]}/messages', json=message(other["id"])).status_code == 409
    assert client.post(f'/api/v1/bus/runs/{run["id"]}/messages', json=message(agent["id"], delivery="direct")).status_code == 409


def test_confirmation_dedup_and_body_validation(agents):
    client, _, _, _, setup = agents
    _, run, agent, _ = setup()
    route = f'/api/v1/bus/runs/{run["id"]}/messages'
    intent = message(agent["id"])
    missing = dict(intent)
    missing.pop("confirm_delivery")
    assert client.post(route, json=missing).status_code == 422
    first = client.post(route, json=intent).json()
    assert client.post(route, json=intent).json()["message"]["id"] == first["message"]["id"]
    assert client.post(route, json=message(agent["id"], body={"text": "Changed"})).status_code == 409
    assert client.post(route, json=message(agent["id"], body={"text": "x" * 8193}, idempotency_key="new-message-key-0001")).status_code == 400
    assert client.get(route).json()["next_after"] is None
    assert client.post(route, json=message(agent["id"], idempotency_key="new-message-key-0002")).status_code == 200
    assert client.get(route + "?limit=1").json()["next_after"] == 1
    assert client.get(route + "?limit=1&after=1").json()["next_after"] is None


def test_revocation_cancels_before_dispatch(agents):
    client, service, remote, _, setup = agents
    _, run, agent, _ = setup()
    token, actor = service.auth.issue("token", scopes=["bus:send"], node_ids=[agent["node_id"]])
    result = client.post(f'/api/v1/bus/runs/{run["id"]}/messages', json=message(agent["id"]),
                         headers={"Authorization": "Bearer " + token}).json()
    service.auth.revoke(actor.id)
    asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    assert service.agents.store.get("bus_deliveries", result["deliveries"][0]["id"])["state"] == "cancelled"
    assert remote[agent["id"]]["items"] == {}


def test_lost_reply_preserves_uncertainty_after_revocation(agents, monkeypatch):
    client, service, remote, _, setup = agents
    _, run, agent, _ = setup()
    token, actor = service.auth.issue("token", scopes=["bus:send"], node_ids=[agent["node_id"]])
    result = client.post(f'/api/v1/bus/runs/{run["id"]}/messages', json=message(agent["id"]),
                         headers={"Authorization": "Bearer " + token}).json()
    original = service.agents.remote
    async def lost(*args, **kwargs):
        await original(*args, **kwargs)
        raise Failure("timeout", "Lost reply", 504)
    monkeypatch.setattr(service.agents, "remote", lost)
    with pytest.raises(Failure):
        asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    identity = result["deliveries"][0]["id"]
    assert service.agents.store.get("bus_deliveries", identity)["state"] == "host-uncertain"
    service.auth.revoke(actor.id)
    monkeypatch.setattr(service.agents, "remote", original)
    asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    assert service.agents.store.get("bus_deliveries", identity)["state"] == "tool-read"
    assert len(remote[agent["id"]]["items"]) == 1


def test_agent_outbox_bound_sender_and_ack_dedup(agents):
    client, service, remote, _, setup = agents
    _, run, first, _ = setup()
    _, _, second, _ = setup(1, run)
    item = {"id": "a" * 32, "type": "note", "body": {"text": "Reply"}, "recipient_ids": [second["id"]],
            "reply_to": None, "idempotency_key": "a" * 32, "delivery": "inbox"}
    remote[first["id"]]["outbox"] = [item]
    async def exchange():
        for _ in range(3):
            await service.agents.exchange(service.agents.store.get("agents", first["id"]))
    asyncio.run(exchange())
    messages = client.get(f'/api/v1/bus/runs/{run["id"]}/messages').json()["messages"]
    assert len(messages) == 1 and messages[0]["sender_id"] == first["id"]
    assert remote[first["id"]]["outbox"] == []
    remote[first["id"]]["outbox"] = [{**item, "id": "b" * 32, "idempotency_key": "b" * 32, "sender_id": second["id"]}]
    asyncio.run(service.agents.exchange(service.agents.store.get("agents", first["id"])))
    saved = service.agents.store.get("agents", first["id"])
    assert saved["outbox_rejections"][0]["code"] == "invalid_message"
    assert len(service.bus.messages(run["id"])) == 1


def test_launch_lost_reply_does_not_create_another_terminal(agents, monkeypatch):
    client, service, _, _, setup = agents
    _, _, agent, intent = setup()
    saved = service.agents.store.get("agents", agent["id"])
    saved["state"] = "unknown"
    service.agents.store.save("agents", saved)
    async def refuse(*args, **kwargs):
        raise AssertionError("A retained launch must never be dispatched again.")
    monkeypatch.setattr(service.agents, "remote", refuse)
    assert client.post("/api/v1/agents", json=intent).json()["state"] == "unknown"
    assert len(service.terminals.all()) == 1


def test_schema_three_migration_preserves_credentials_and_rows(tmp_path):
    import sqlite3
    import time

    from ficc.auth import Auth, digest
    from ficc.store import Store
    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    path = folder / "state.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE credentials(id TEXT PRIMARY KEY,digest TEXT UNIQUE,kind TEXT,label TEXT,scopes TEXT,nodes TEXT,expires REAL,csrf TEXT,roots TEXT); PRAGMA user_version=3;")
        db.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?,?)", ("existing", digest("secret"), "token", "Original", '["terminals:read"]', "null", time.time() + 60, "csrf", "null"))
    path.chmod(0o600)
    store = Store(path)
    try:
        assert store.db.execute("PRAGMA user_version").fetchone()[0] == 4
        assert Auth(store).resolve("secret").scopes == ["terminals:read"]
        with pytest.raises(Failure):
            Auth(store).resolve("secret").require("agents:execute")
    finally:
        store.close()


@pytest.mark.parametrize("count", [1, 64])
def test_slow_relay_does_not_block_control_of_healthy_agent(agents, monkeypatch, count):
    _, service, _, _, setup = agents
    _, _, agent, _ = setup()
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        original = service.agents.exchange
        async def slow(value):
            if value["id"] == agent["id"]:
                return await original(value)
            entered.set()
            await release.wait()
        monkeypatch.setattr(service.agents, "exchange", slow)
        values = []
        for index in range(count):
            value = service.agents.store.get("agents", agent["id"])
            value.update(id=f"{index + 50000:032x}", key=f"slow-{index}")
            service.agents.store.save("agents", value)
            values.append(value["id"])
        poll = asyncio.create_task(service.agents.poll())
        await entered.wait()
        try:
            actor = service.agents.store.get("agents", agent["id"])["actor"]
            async with asyncio.timeout(1):
                result = await service.agents.action(agent["id"], actor, "stop")
            assert result["state"] == "stopped"
        finally:
            release.set()
            poll.cancel()
            await asyncio.gather(poll, return_exceptions=True)
    asyncio.run(scenario())
