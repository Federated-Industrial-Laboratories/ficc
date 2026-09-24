# SPDX-License-Identifier: Apache-2.0
"""Exercise exact agent Stop through real PTY attachment cleanup."""

import asyncio
import json
import sys
from types import SimpleNamespace

import pytest
from conftest import node

from ficc.service import Service
from ficc.settings import Settings
from ficc.terminal_stream import attachment


@pytest.mark.parametrize("count", [1, 64])
def test_attached_stop_releases_capacity_and_repairs_repeated_stop(tmp_path, monkeypatch, count):
    service = Service(Settings(state_dir=tmp_path / "state", control=False))
    _, principal = service.auth.issue("token")
    selected = node(1)
    selected.update(helper_version="3", capabilities={"agents": True, "terminals_tmux": True})
    service.store.save_node(selected)
    calls = []
    async def arguments(value, actor):
        return [sys.executable, "-c", "import time;time.sleep(30)"]
    async def remote(node_id, action, body, check=None):
        check()
        calls.append(body["agent_id"])
        return {"state": "stopped", "runtime_session_id": None, "last_contact": 1}
    monkeypatch.setattr(service.terminals, "arguments", arguments)
    monkeypatch.setattr(service.agents, "remote", remote)
    async def scenario():
        for index in range(count):
            tid = f"{index + 1000:032x}"
            agent = service.agents.store.new("agents", principal.id, str(index), {}, node_id=selected["id"],
                fingerprint=selected["fingerprint"], terminal_id=tid, state="ready", run_id="a" * 32, outbox_acks=[])
            service.agents.store.save("agents", agent)
            service.terminals.save({"id": tid, "actor": principal.id, "key": str(index), "digest": "fixture",
                "node_id": selected["id"], "node_name": selected["name"], "account": selected["account"],
                "fingerprint": selected["fingerprint"], "label": "Fixture", "mode": "tmux", "state": "detached",
                "cols": 80, "rows": 24, "created_at": 0, "error": None, "agent_id": agent["id"]})
            ticket = service.terminals.ticket(tid, principal.id)["ticket"]
            class Socket:
                headers = {"host": "127.0.0.1:8179", "origin": "http://127.0.0.1:8179"}
                url = SimpleNamespace(query="")
                def __init__(self):
                    self.entered, self.closed = asyncio.Event(), False
                async def accept(self):
                    pass
                async def receive_text(self):
                    return json.dumps({"type": "auth", "ticket": ticket})
                async def send_json(self, value):
                    if value.get("state") == "attached":
                        self.entered.set()
                async def send_bytes(self, value):
                    pass
                async def receive(self):
                    await asyncio.Event().wait()
                async def close(self, **kwargs):
                    self.closed = True
            socket = Socket()
            task = asyncio.create_task(attachment(socket, service.terminals, tid,
                {"http://127.0.0.1:8179"}, {"127.0.0.1:8179"}))
            try:
                async with asyncio.timeout(5):
                    await socket.entered.wait()
                    result = await service.agents.action(agent["id"], principal.id, "stop")
                assert result["state"] == service.terminals.get(tid)["state"] == "stopped"
                assert socket.closed and task.done() and not service.terminals.active
                assert not service.terminals.busy(selected["id"])
                # A saved pre-fix terminal is repaired without another remote Stop.
                terminal = service.terminals.get(tid)
                terminal["state"] = "detached"
                service.terminals.save(terminal)
                await service.agents.action(agent["id"], principal.id, "stop")
                assert service.terminals.get(tid)["state"] == "stopped"
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        assert len(calls) == len(set(calls)) == count
    try:
        asyncio.run(scenario())
    finally:
        service.close()
