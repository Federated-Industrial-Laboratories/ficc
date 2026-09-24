# SPDX-License-Identifier: Apache-2.0
"""Validate local replies and preserve permanent refusals without queue poisoning."""

import asyncio
import json

import pytest
from conftest import node
from ficc_node import agent_archive, agent_tool
from ficc_node import agent_spool as spool
from ficc_node import agents as node_agents

from ficc.errors import Failure
from ficc.service import Service
from ficc.settings import Settings


def request(key, **extra):
    return {"type": "note", "body": {"text": "Observation"}, "recipient_ids": [], "reply_to": None,
            "idempotency_key": key, "delivery": "inbox", **extra}


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(node_agents.terminals, "call", lambda *args: 0)
    service = Service(Settings(state_dir=tmp_path / "state", control=False))
    _, principal = service.auth.issue("token")
    value = node(1)
    value.update(helper_version="3", capabilities={"agents": True})
    service.store.save_node(value)
    run = service.bus.create({"name": "outbox", "idempotency_key": "outbox-run-0000001"}, principal.id)
    async def remote(node_id, action, body, check=None):
        check()
        return node_agents.dispatch({"version": "3", "action": "agent." + action, **body})
    monkeypatch.setattr(service.agents, "remote", remote)
    def create(index=1):
        terminal = f"{index + 1000:032x}"
        agent = service.agents.store.new("agents", principal.id, str(index), {}, node_id=value["id"],
            fingerprint=value["fingerprint"], terminal_id=terminal, state="ready", run_id=run["id"], outbox_acks=[])
        service.agents.store.save("agents", agent)
        service.terminals.save({"id": terminal, "actor": principal.id, "key": str(index), "digest": "fixture",
                               "state": "detached", "mode": "tmux"})
        spec = {"controller_id": service.agents.controller, "agent_id": agent["id"], "run_id": run["id"],
                "terminal_controller": service.terminals.controller, "terminal_id": terminal, "delivery_method": "inbox"}
        folder = spool.base(service.agents.controller, agent["id"])
        spool.write(folder / "spec.json", spec)
        spool.write(folder / "runtime.json", {"state": "ready", "session_id": agent["id"]})
        return folder, agent
    yield service, principal, run, create
    service.close()


@pytest.mark.parametrize("extra", [
    {"body": {"text": ""}}, {"body": {"text": "bad\x00text"}}, {"body": {"text": "x" * 8193}},
    {"type": "unknown"}, {"type": "finding", "body": {"claim": "Claim", "provenance": "invented"}},
    {"type": "rank", "body": {"re": "id", "score": 2, "basis": "Basis"}},
    {"type": "handoff", "body": {"path": "file", "status": "done"}}, {"body": {"text": "Valid", "extra": True}},
])
def test_local_invalid_body_is_not_published(local, extra):
    service, _, _, create = local
    folder, agent = create()
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    with pytest.raises(ValueError):
        agent_tool.operate(service.agents.controller, agent["id"], "send", request("1" * 32, **extra))
    # Lock creation is allowed; no message content was admitted.
    assert {p.name: p.read_bytes() for p in folder.iterdir() if p.name != "lock"} == before


@pytest.mark.parametrize("count", [1, 64])
def test_permanent_rejection_keeps_exact_bytes_and_later_reply_progresses(local, monkeypatch, count):
    service, _, run, create = local
    controller = service.agents.controller
    for index in range(count):
        folder, agent = create(index)
        invalid = request("1" * 32, type="answer", body={"text": f"Unknown reference {index}", "re": "missing-1"})
        valid = request("2" * 32, body={"text": f"Later valid reply {index}"})
        agent_tool.operate(controller, agent["id"], "send", invalid)
        agent_tool.operate(controller, agent["id"], "send", valid)
        path = folder / ("outbox-" + "1" * 32 + ".json")
        original = json.dumps(spool.read(path), indent=3).encode() + b"\n"
        path.write_bytes(original)
        async def exchanges():
            for _ in range(3):
                await service.agents.exchange(service.agents.store.get("agents", agent["id"]))
        asyncio.run(exchanges())
        assert not list(folder.glob("outbox-*.json"))
        assert (folder / ("rejected-" + "1" * 32 + ".json")).read_bytes() == original
        saved = service.agents.store.get("agents", agent["id"])
        rejection = saved["outbox_rejections"][0]
        assert rejection["id"] == "1" * 32 and rejection["code"] == "invalid_message"
        listed = agent_tool.operate(controller, agent["id"], "rejects", {})
        assert listed["rejections"][0]["state"] == "host-rejected" and listed["next_after"] is None
        assert agent_tool.operate(controller, agent["id"], "rejected", {"idempotency_key": "1" * 32})["message"]["body"] == invalid["body"]
        assert agent_tool.operate(controller, agent["id"], "send", invalid)["state"] == "host-rejected"
        assert agent_tool.operate(controller, agent["id"], "send", valid)["state"] == "host-stored"
        with pytest.raises(ValueError, match="different rejected"):
            agent_tool.operate(controller, agent["id"], "send", {**invalid, "body": {"text": "Changed", "re": "missing-1"}})
        # Explicit archival retains refused bytes while reclaiming the active namespace.
        spool.write(folder / "runtime.json", {"state": "stopped", "session_id": agent["id"]})
        with monkeypatch.context() as patch:
            patch.setattr(node_agents.terminals, "call", lambda *args: 1)
            archive = agent_archive.retire(controller, agent["id"])
        from pathlib import Path
        assert (Path(archive["archive"]) / path.name.replace("outbox-", "rejected-")).read_bytes() == original
    messages = service.bus.messages(run["id"])
    assert len(messages) == count and len({m["sender_id"] for m in messages}) == count
    assert {m["body"]["text"] for m in messages} == {f"Later valid reply {i}" for i in range(count)}


def test_lost_rejection_ack_and_transient_failure_preserve_items(local, monkeypatch):
    service, _, run, create = local
    folder, agent = create()
    controller = service.agents.controller
    invalid = request("1" * 32, reply_to="f" * 32)
    valid = request("2" * 32)
    for value in (invalid, valid):
        agent_tool.operate(controller, agent["id"], "send", value)
    send = service.bus.send
    def transient(run_id, body, actor, sender=None):
        if body["idempotency_key"] == "2" * 32:
            raise Failure("capacity", "Temporary capacity refusal", 409)
        return send(run_id, body, actor, sender)
    monkeypatch.setattr(service.bus, "send", transient)
    asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    saved = service.agents.store.get("agents", agent["id"])
    assert len(saved["outbox_acks"]) == 1 and saved["outbox_rejections"][0]["code"] == "invalid_reply"
    remote = service.agents.remote
    async def lost(*args, **kwargs):
        await remote(*args, **kwargs)
        raise Failure("timeout", "Lost acknowledgement reply", 504)
    monkeypatch.setattr(service.agents, "remote", lost)
    with pytest.raises(Failure):
        asyncio.run(service.agents.exchange(saved))
    assert len(list(folder.glob("outbox-*.json"))) == 1
    monkeypatch.setattr(service.agents, "remote", remote)
    monkeypatch.setattr(service.bus, "send", send)
    for _ in range(2):
        asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    assert len(service.bus.messages(run["id"])) == 1 and not list(folder.glob("outbox-*.json"))
    assert len(list(folder.glob("rejected-*.json"))) == 1


def test_revoked_launch_grant_does_not_become_permanent_refusal(local):
    service, principal, run, create = local
    folder, agent = create()
    for key in ("1", "2"):
        agent_tool.operate(service.agents.controller, agent["id"], "send", request(key * 32, reply_to="f" * 32))
    service.auth.revoke(principal.id)
    service.auth.issue("token")
    for _ in range(2):
        asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    saved = service.agents.store.get("agents", agent["id"])
    assert saved["actor"] == principal.id and saved["outbox_acks"] == [] and not saved.get("outbox_rejections")
    assert len(list(folder.glob("outbox-*.json"))) == 2 and not service.bus.messages(run["id"])


def test_rejection_publication_failure_retains_retryable_original(local, monkeypatch):
    from ficc_node import agent_outbox
    service, _, _, create = local
    folder, agent = create()
    controller = service.agents.controller
    agent_tool.operate(controller, agent["id"], "send", request("1" * 32, reply_to="f" * 32))
    path = folder / ("outbox-" + "1" * 32 + ".json")
    original = path.read_bytes()
    asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    replace = agent_outbox.os.replace
    def fail(source, target, *args, **kwargs):
        if target.name.startswith("rejected-"):
            raise OSError("Injected rejection retention boundary failure")
        return replace(source, target, *args, **kwargs)
    monkeypatch.setattr(agent_outbox.os, "replace", fail)
    with pytest.raises(OSError):
        asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    assert path.read_bytes() == original and list(folder.glob("rejection-*.json"))
    monkeypatch.setattr(agent_outbox.os, "replace", replace)
    asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    assert not path.exists() and (folder / path.name.replace("outbox-", "rejected-")).read_bytes() == original


def test_rejection_summary_is_bounded_and_full_node_history_is_pageable(local):
    service, _, _, create = local
    folder, agent = create()
    controller = service.agents.controller
    for index in range(17):
        agent_tool.operate(controller, agent["id"], "send", request(f"{index + 1:032x}", reply_to="f" * 32))
    for _ in range(4):
        asyncio.run(service.agents.exchange(service.agents.store.get("agents", agent["id"])))
    saved = service.agents.store.get("agents", agent["id"])
    assert len(saved["outbox_rejections"]) == 16 and saved["outbox_rejections"][0]["id"] == f"{2:032x}"
    after, seen = None, []
    while True:
        page = agent_tool.operate(controller, agent["id"], "rejects", {"after": after})
        assert len(page["rejections"]) <= 8
        seen.extend(r["id"] for r in page["rejections"])
        after = page["next_after"]
        if after is None:
            break
    assert seen == [f"{index + 1:032x}" for index in range(17)]
    assert len(list(folder.glob("rejected-*.json"))) == 17
