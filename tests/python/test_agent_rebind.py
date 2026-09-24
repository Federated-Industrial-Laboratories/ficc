# SPDX-License-Identifier: Apache-2.0
"""Keep confirmed Codex rebinds aligned with submission and receipt identities."""

import time
from pathlib import Path

import pytest
from ficc_node import agent_adapter as adapter
from ficc_node import agent_binding, agents
from ficc_node import agent_runner as runner
from ficc_node import agent_spool as spool
from ficc_node.agent_codex import observe


@pytest.mark.parametrize("count", [1, 64])
def test_runner_uses_confirmed_thread_and_ignores_stale_observation(tmp_path, monkeypatch, count):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(agents.terminals, "call", lambda *args: 0)
    monkeypatch.setattr(runner, "alive", lambda process: True)
    monkeypatch.setattr(runner, "stop_group", lambda process: None)
    monkeypatch.setattr(runner.signal, "signal", lambda *args: None)
    monkeypatch.setattr(runner.time, "sleep", lambda duration: None)
    for index in range(count):
        controller, agent = "c" * 32, f"{index + 1:032x}"
        first, second = f"thread-A-{index}", f"thread-B-{index}"
        folder = spool.base(controller, agent)
        spec = {"controller_id": controller, "agent_id": agent, "run_id": "d" * 32,
            "terminal_controller": "e" * 32, "terminal_id": f"{index + 1000:032x}", "delivery_method": "direct",
            "profile": {"adapter": "codex", "argv": ["fixture-codex"], "workspace": str(tmp_path)}}
        spool.write(folder / "spec.json", spec)
        spool.write(folder / "runtime.json", {"state": "starting", "session_id": None})
        delivery = {"id": f"{index + 1000:032x}", "message_id": "9" * 32, "agent_id": agent,
            "run_id": spec["run_id"], "sender_id": "sender", "type": "note", "body": {"text": f"For B {index}"},
            "method": "direct", "authorization_expires_at": time.time() + 60}
        calls, proof = [], {}
        rebound = False
        class Runtime:
            def __init__(self, path):
                self.events = []
            def call(self, method, params):
                calls.append((method, params))
                if method == "thread/start":
                    return {"thread": {"id": first}}
                if method == "thread/read":
                    if not rebound:
                        self.events.append({"method": "thread/started", "params": {"thread": {"id": second}}})
                    return {"thread": {"id": params["threadId"]}}
                if method == "thread/queue/add":
                    assert params["threadId"] == second
                    proof.update(clientId=params["clientUserMessageId"], content=params["input"], type="userMessage")
                    return {"queuedSubmission": {"id": "queued", "clientUserMessageId": delivery["id"]}}
                if method == "thread/items/list":
                    assert params["threadId"] == second
                    return {"data": [{"item": proof}], "nextCursor": None}
                raise AssertionError(method)
            def close(self):
                pass
        class Process:
            returncode = 0
            def __init__(self, command, **kwargs):
                self.polls = 0
                if "app-server" in command:
                    Path(command[-1].removeprefix("unix://")).touch(mode=0o600)
            def poll(self):
                self.polls += 1
                return None if self.polls < 6 else 0
            def terminate(self):
                pass
            def wait(self, timeout=None):
                return 0
        original = adapter.dispatch
        def dispatch(c, a, action, request):
            nonlocal rebound
            if action == "next" and not rebound:
                assert spool.read(folder / "runtime.json")["state"] == "suspended"
                result = agents.dispatch({"version": "3", "action": "agent.rebind", "controller_id": c,
                    "agent_id": a, "runtime_session_id": second})
                assert result["state"] == "ready" and result["runtime_session_id"] == second
                rebound = True
                spool.write(folder / ("inbox-" + delivery["id"] + ".json"), delivery)
                spool.receipt(folder, delivery["id"], "node-stored")
                # An older observation must not undo the operator's committed binding.
                original(c, a, "suspend", {"session_id": first, "expected_session_id": first, "binding_revision": 0})
                assert spool.read(folder / "runtime.json")["state"] == "ready"
            return original(c, a, action, request)
        monkeypatch.setattr(runner, "RPC", Runtime)
        monkeypatch.setattr(agent_binding, "RPC", Runtime)
        monkeypatch.setattr(runner.subprocess, "Popen", Process)
        monkeypatch.setattr(adapter, "dispatch", dispatch)
        runner.codex(controller, agent, spec, {})
        monkeypatch.setattr(adapter, "dispatch", original)
        queued = [p for method, p in calls if method == "thread/queue/add"]
        assert len(queued) == 1 and queued[0]["threadId"] == second
        receipt = spool.read(folder / ("receipt-" + delivery["id"] + ".json"))
        assert receipt["state"] == "session-included" and receipt["session_id"] == second


@pytest.mark.parametrize("state", ["uncertain", "adapter-submitted"])
def test_changed_thread_refuses_old_unresolved_but_same_thread_recovers(tmp_path, monkeypatch, state):
    monkeypatch.setenv("HOME", str(tmp_path))
    controller, agent = "c" * 32, "a" * 32
    folder = spool.base(controller, agent)
    spec = {"controller_id": controller, "agent_id": agent, "delivery_method": "direct"}
    spool.write(folder / "spec.json", spec)
    spool.write(folder / "runtime.json", {"state": "suspended", "session_id": "old", "observed_session_id": "new"})
    item = {"id": "b" * 32, "method": "direct", "sender_id": "sender", "run_id": "d" * 32,
            "message_id": "e" * 32, "type": "note", "body": {"text": "Original"}}
    spool.write(folder / ("inbox-" + item["id"] + ".json"), item)
    spool.receipt(folder, item["id"], state, session_id="old")
    with spool.locked(controller, agent):
        with pytest.raises(ValueError, match="old-session"):
            agent_binding.rebind(folder, spec, "new")
    # Same-thread recovery preserves the unresolved receipt and allows observation.
    runtime = spool.read(folder / "runtime.json")
    runtime["observed_session_id"] = "old"
    spool.write(folder / "runtime.json", runtime)
    with spool.locked(controller, agent):
        recovered = agent_binding.rebind(folder, spec, "old")
    assert recovered["state"] == "ready"
    adapter.dispatch(controller, agent, "suspend", {"session_id": "new"})
    class Runtime:
        events = []
        def call(self, method, request):
            return {"data": [{"item": {"type": "userMessage", "clientId": item["id"],
                "content": [{"type": "text", "text": adapter.text(item)}]}}]}
    assert observe(Runtime(), controller, agent, "old", recovered["binding_revision"])
    with spool.locked(controller, agent):
        assert agent_binding.rebind(folder, spec, "new")["session_id"] == "new"
    with pytest.raises(ValueError, match="different runtime"):
        adapter.dispatch(controller, agent, "receipt", {"session_id": "new", "delivery_id": item["id"], "state": "session-included"})
    runtime = spool.read(folder / "runtime.json")
    runtime.update(state="suspended", observed_session_id="new")
    spool.write(folder / "runtime.json", runtime)
    with spool.locked(controller, agent):
        assert agent_binding.rebind(folder, spec, "new")["state"] == "ready"


@pytest.mark.parametrize("kind", ["waiting", "included", "wrong-thread", "oversized"])
def test_unavailable_item_projection_uses_bounded_thread_read(tmp_path, monkeypatch, kind):
    from ficc_node.agent_rpc import RPCError
    monkeypatch.setenv("HOME", str(tmp_path))
    controller, agent, thread = "c" * 32, "a" * 32, "exact-thread"
    folder = spool.base(controller, agent)
    spool.write(folder / "spec.json", {"delivery_method": "direct"})
    spool.write(folder / "runtime.json", {"state": "ready", "session_id": thread})
    item = {"id": "b" * 32, "method": "direct", "sender_id": "sender", "run_id": "d" * 32,
            "message_id": "e" * 32, "type": "note", "body": {"text": "Original"}}
    spool.write(folder / ("inbox-" + item["id"] + ".json"), item)
    spool.receipt(folder, item["id"], "uncertain", session_id=thread)
    calls = []
    class Runtime:
        events = []
        def call(self, method, request):
            calls.append((method, request))
            if method == "thread/items/list":
                raise RPCError(method, {"code": -32601, "message": "thread/items/list is not supported yet"})
            assert request == {"threadId": thread, "includeTurns": True}
            rows = [] if kind == "waiting" else [{"type": "userMessage", "clientId": item["id"],
                "content": [{"type": "text", "text": adapter.text(item)}]}]
            if kind == "oversized":
                rows *= 257
            return {"thread": {"id": "other" if kind == "wrong-thread" else thread, "turns": [{"items": rows}]}}
    assert observe(Runtime(), controller, agent, thread) is (kind in {"waiting", "included"})
    runtime = spool.read(folder / "runtime.json")
    receipt = spool.read(folder / ("receipt-" + item["id"] + ".json"))
    assert runtime["state"] == ("ready" if kind in {"waiting", "included"} else "suspended")
    assert receipt["state"] == ("session-included" if kind == "included" else "uncertain")
    assert [method for method, _ in calls] == ["thread/items/list", "thread/read"]
