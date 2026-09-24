# SPDX-License-Identifier: Apache-2.0
"""Verify bounded node inboxes, runtime uncertainty and exact identity routing."""

import os
import time

import pytest
from ficc_node import agent_adapter as adapter
from ficc_node import agent_spool as spool
from ficc_node import agent_tool, agents


@pytest.fixture
def namespace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(agents.terminals, "call", lambda *args: 0)
    controller = "c" * 32
    def create(index=1, method="inbox"):
        identity = f"{index:032x}"
        folder = spool.base(controller, identity)
        spec = {"agent_id": identity, "controller_id": controller, "run_id": "d" * 32,
                "terminal_controller": "e" * 32, "terminal_id": f"{index + 1000:032x}",
                "delivery_method": method}
        with spool.locked(controller, identity):
            spool.write(folder / "spec.json", spec)
            spool.write(folder / "runtime.json", {"state": "ready", "session_id": identity})
        return folder, spec
    return controller, create


def item(spec, index=1, **extra):
    return {"id": f"{index:032x}", "message_id": f"{index + 2000:032x}", "agent_id": spec["agent_id"],
            "run_id": spec["run_id"], "sender_id": "sender", "type": "note", "body": {"text": "Observation"},
            "method": spec["delivery_method"], "authorization_expires_at": time.time() + 60, **extra}


def exchange(spec, deliveries=None, receipts=None, acks=None):
    return agents.dispatch({"version": "3", "action": "agent.exchange", "controller_id": spec["controller_id"],
        "agent_id": spec["agent_id"], "deliveries": deliveries or [], "receipt_ids": receipts or [], "outbox_acks": acks or []})


@pytest.mark.parametrize("count", [1, 64])
def test_distinct_routing_duplicate_exchange_and_tool_receipt(namespace, count):
    controller, create = namespace
    for index in range(1, count + 1):
        folder, spec = create(index)
        delivery = item(spec, index)
        assert exchange(spec, [delivery])["state"] == "ready"
        exchange(spec, [delivery])
        assert len(list(folder.glob("inbox-*.json"))) == 1
        assert agent_tool.operate(controller, spec["agent_id"], "list", {})["messages"] == [delivery]
        assert exchange(spec, receipts=[delivery["id"]])["receipts"][0]["state"] == "node-stored"
        assert agent_tool.operate(controller, spec["agent_id"], "read", {"delivery_id": delivery["id"]}) == delivery
        assert exchange(spec, receipts=[delivery["id"]])["receipts"][0]["state"] == "tool-read"
        if count > 1:
            with pytest.raises(ValueError, match="recipient"):
                exchange(spec, [item(spec, 100 + index, agent_id=f"{index + 1:032x}")])


def test_conflicting_delivery_and_expired_direct_refused(namespace):
    controller, create = namespace
    _, spec = create(method="direct")
    delivery = item(spec)
    exchange(spec, [delivery])
    with pytest.raises(ValueError, match="conflicts"):
        exchange(spec, [{**delivery, "body": {"text": "changed"}}])
    expired = item(spec, 2, authorization_expires_at=0)
    exchange(spec, [expired])
    first = adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": spec["agent_id"]})
    assert first["messages"] == [delivery]
    assert adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": spec["agent_id"]}) == {"messages": []}
    receipts = exchange(spec, receipts=[delivery["id"], expired["id"]])["receipts"]
    assert [value["state"] for value in receipts] == ["uncertain", "cancelled"]


def test_session_switch_suspends_and_explicit_rebind_is_exact(namespace):
    controller, create = namespace
    _, spec = create(method="direct")
    exchange(spec, [item(spec)])
    assert adapter.dispatch(controller, spec["agent_id"], "register", {"session_id": "new-session"})["state"] == "suspended"
    assert adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": "new-session"}) == {"messages": []}
    request = {"version": "3", "action": "agent.rebind", "controller_id": controller, "agent_id": spec["agent_id"]}
    with pytest.raises(ValueError):
        agents.dispatch({**request, "runtime_session_id": "wrong"})
    assert agents.dispatch({**request, "runtime_session_id": "new-session"})["runtime_session_id"] == "new-session"
    assert len(adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": "new-session"})["messages"]) == 1


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "mode", "unknown", "oversized"])
def test_hostile_spool_is_refused(namespace, tmp_path, kind):
    controller, create = namespace
    folder, spec = create()
    path = folder / "inbox-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"
    if kind == "symlink":
        path.symlink_to(tmp_path / "outside")
    elif kind == "hardlink":
        os.link(folder / "spec.json", path)
    elif kind == "mode":
        path.write_text("{}")
        path.chmod(0o644)
    elif kind == "unknown":
        path = folder / "surprise.json"
        path.write_text("{}")
        path.chmod(0o600)
    else:
        path.write_bytes(b"x" * 32769)
        path.chmod(0o600)
    with pytest.raises((ValueError, OSError)):
        agent_tool.operate(controller, spec["agent_id"], "list", {})


def test_full_inbox_and_outbox_retries(namespace):
    controller, create = namespace
    folder, spec = create()
    for start in range(1, 257, 8):
        exchange(spec, [item(spec, index) for index in range(start, start + 8)])
    with pytest.raises(ValueError, match="full"):
        exchange(spec, [item(spec, 1000)])
    request = {"type": "note", "body": {"text": "Reply"}, "recipient_ids": ["f" * 32], "reply_to": None,
               "idempotency_key": "b" * 32, "delivery": "direct"}
    assert agent_tool.operate(controller, spec["agent_id"], "send", request)["state"] == "node-stored"
    agent_tool.operate(controller, spec["agent_id"], "send", request)
    assert len(list(folder.glob("outbox-*.json"))) == 1
    assert exchange(spec)["outbox"][0]["delivery"] == "direct"
    with pytest.raises(ValueError, match="different"):
        agent_tool.operate(controller, spec["agent_id"], "send", {**request, "body": {"text": "changed"}})
    exchange(spec, acks=["b" * 32])
    assert exchange(spec)["outbox"] == []


def test_interrupted_receipt_publication_recovers_without_duplicate(namespace, monkeypatch):
    _, create = namespace
    folder, spec = create()
    delivery = item(spec)
    original = spool.receipt
    def fail(*args, **kwargs):
        raise OSError("Injected receipt publication failure")
    monkeypatch.setattr(spool, "receipt", fail)
    with pytest.raises(OSError):
        exchange(spec, [delivery])
    assert (folder / ("inbox-" + delivery["id"] + ".json")).exists()
    monkeypatch.setattr(spool, "receipt", original)
    result = exchange(spec, receipts=[delivery["id"]])
    assert result["receipts"][0]["state"] == "node-stored"
    assert len(list(folder.glob("inbox-*.json"))) == 1


def test_runtime_submission_is_never_blindly_replayed(namespace, monkeypatch):
    controller, create = namespace
    _, spec = create(method="direct")
    delivery = item(spec)
    exchange(spec, [delivery])
    assert adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": spec["agent_id"]})["messages"] == [delivery]
    for _ in range(3):
        assert adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": spec["agent_id"]}) == {"messages": []}
    adapter.dispatch(controller, spec["agent_id"], "receipt", {"session_id": spec["agent_id"], "delivery_id": delivery["id"], "state": "session-included"})
    assert exchange(spec, receipts=[delivery["id"]])["receipts"][0]["state"] == "session-included"


def test_explicit_node_archive_reclaims_active_capacity(namespace, monkeypatch):
    from ficc_node import agent_archive
    controller, create = namespace
    monkeypatch.setattr(spool, "MAX_AGENTS", 1)
    folder, spec = create()
    spool.write(folder / "runtime.json", {"state": "stopped", "session_id": spec["agent_id"]})
    with pytest.raises(ValueError, match="full"):
        create(2)
    monkeypatch.setattr(agents.terminals, "call", lambda *args: 1)
    result = agent_archive.retire(controller, spec["agent_id"])
    assert result["state"] == "archived" and not folder.exists()
    assert agent_archive.retire(controller, spec["agent_id"]) == result
    new_folder, _ = create(2)
    assert new_folder.exists()
    with pytest.raises(ValueError, match="archived"):
        create()


@pytest.mark.parametrize("state", ["ready", "unknown", "starting"])
def test_archive_refuses_active_or_uncertain_agent(namespace, state):
    from ficc_node import agent_archive
    controller, create = namespace
    folder, spec = create()
    spool.write(folder / "runtime.json", {"state": state, "session_id": spec["agent_id"]})
    with pytest.raises(ValueError, match="active or uncertain"):
        agent_archive.retire(controller, spec["agent_id"])
    assert folder.exists()


def test_acknowledged_outbox_identity_cannot_be_reused(namespace):
    controller, create = namespace
    _, spec = create()
    request = {"type": "note", "body": {"text": "Original"}, "recipient_ids": [], "reply_to": None,
               "idempotency_key": "b" * 32, "delivery": "inbox"}
    agent_tool.operate(controller, spec["agent_id"], "send", request)
    exchange(spec, acks=["b" * 32])
    assert agent_tool.operate(controller, spec["agent_id"], "send", request)["state"] == "host-stored"
    with pytest.raises(ValueError, match="different acknowledged"):
        agent_tool.operate(controller, spec["agent_id"], "send", {**request, "body": {"text": "Replacement"}})
    assert exchange(spec)["outbox"] == []


def test_spool_byte_cap_refuses_before_publication(namespace, monkeypatch):
    _, create = namespace
    folder, spec = create()
    before = {path.name: path.read_bytes() for path in folder.iterdir()}
    monkeypatch.setattr(spool, "MAX_BYTES", sum(len(raw) for raw in before.values()) + 10)
    with pytest.raises(ValueError, match="capacity"):
        exchange(spec, [item(spec)])
    assert {path.name: path.read_bytes() for path in folder.iterdir()} == before


def test_codex_inclusion_requires_bound_identity_and_exact_content(namespace):
    from ficc_node.agent_codex import reconcile
    controller, create = namespace
    _, spec = create(method="direct")
    delivery = item(spec)
    exchange(spec, [delivery])
    adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": spec["agent_id"]})
    class Runtime:
        events = []
        content = "Changed"
        def call(self, method, request):
            assert request["threadId"] == spec["agent_id"]
            return {"data": [{"item": {"type": "userMessage", "clientId": delivery["id"],
                     "content": [{"type": "text", "text": self.content}]}}], "nextCursor": None}
    runtime = Runtime()
    with pytest.raises(ValueError, match="conflicting content"):
        reconcile(runtime, controller, spec["agent_id"], spec["agent_id"])
    assert exchange(spec, receipts=[delivery["id"]])["receipts"][0]["state"] == "uncertain"
    runtime.content = adapter.text(delivery)
    reconcile(runtime, controller, spec["agent_id"], spec["agent_id"])
    assert exchange(spec, receipts=[delivery["id"]])["receipts"][0]["state"] == "session-included"


def test_generic_read_does_not_clear_uncertain_direct_submission(namespace):
    controller, create = namespace
    _, spec = create(method="direct")
    delivery = item(spec)
    exchange(spec, [delivery])
    adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": spec["agent_id"]})
    agent_tool.operate(controller, spec["agent_id"], "read", {"delivery_id": delivery["id"]})
    assert exchange(spec, receipts=[delivery["id"]])["receipts"][0]["state"] == "uncertain"


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("boundary", ["before", "after"])
def test_actual_process_exit_at_runtime_receipt_boundary(namespace, count, boundary):
    import subprocess
    import sys
    from pathlib import Path
    controller, create = namespace
    specifications = []
    for index in range(1, count + 1):
        _, spec = create(index, method="direct")
        exchange(spec, [item(spec)])
        specifications.append(spec)
    code = r'''
import os,sys
from pathlib import Path
from ficc_node import agent_spool as spool, agent_adapter as adapter
controller,count,boundary=sys.argv[1],int(sys.argv[2]),sys.argv[3]
last=f"{count:032x}"
original=os.replace
def replace(source,target,*args,**kwargs):
    selected=Path(target).parent.name==last and Path(target).name.startswith("receipt-")
    if selected and boundary=="before":os._exit(77)
    original(source,target,*args,**kwargs)
    if selected and boundary=="after":os._exit(77)
os.replace=replace
for index in range(1,count+1):
    identity=f"{index:032x}"
    adapter.dispatch(controller,identity,"next",{"session_id":identity})
'''
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[2] / "node")}
    result = subprocess.run([sys.executable, "-c", code, controller, str(count), boundary], env=env, timeout=30)
    assert result.returncode == 77
    admitted = []
    for spec in specifications:
        first = adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": spec["agent_id"]})
        admitted.extend(first["messages"])
        assert adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": spec["agent_id"]}) == {"messages": []}
    assert len(admitted) == (1 if boundary == "before" else 0)
    if admitted:
        assert admitted[0]["agent_id"] == f"{count:032x}"


def test_codex_observation_failure_suspends_without_clearing_receipt(namespace):
    from ficc_node.agent_codex import observe
    controller, create = namespace
    folder, spec = create(method="direct")
    delivery = item(spec)
    exchange(spec, [delivery])
    adapter.dispatch(controller, spec["agent_id"], "next", {"session_id": spec["agent_id"]})
    class Runtime:
        events = []
        def call(self, *args):
            raise ValueError("Oversized or unavailable runtime page")
    assert observe(Runtime(), controller, spec["agent_id"], spec["agent_id"]) is False
    runtime = spool.read(folder / "runtime.json")
    assert runtime["state"] == "suspended" and runtime["observed_session_id"] == spec["agent_id"]
    assert exchange(spec, receipts=[delivery["id"]])["receipts"][0]["state"] == "uncertain"
