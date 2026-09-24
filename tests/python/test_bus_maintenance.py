# SPDX-License-Identifier: Apache-2.0
"""Keep bus identities through export, import, backup and explicit retirement."""

import json

import pytest

from ficc import backup_database, history_state
from ficc.agent_store import AgentStore
from ficc.bus_cli import export_run, import_run
from ficc.bus_schema import portable


def test_portable_export_import_and_closed_archive(console, tmp_path):
    client, service = console
    run = client.post("/api/v1/bus/runs", json={"name": "portable", "idempotency_key": "portable-run-0000001"}).json()
    payload = {"type": "finding", "body": {"claim": "Observed", "provenance": "computed"}, "recipient_ids": [],
               "delivery": "inbox", "reply_to": None, "confirm_delivery": True, "idempotency_key": "portable-message-001"}
    response = client.post(f'/api/v1/bus/runs/{run["id"]}/messages', json=payload)
    assert response.status_code == 200, response.text
    output = tmp_path / "export"
    export_run(service.store, run["id"], output)
    original = portable((output / "messages.jsonl").read_text().splitlines())
    assert original[0]["body"]["id"] == original[0]["agent"] + "-1"
    imported = import_run(service.store, output / "messages.jsonl")
    assert imported["messages"] == 1
    assert import_run(service.store, output / "messages.jsonl")["imported"] is False
    with pytest.raises(ValueError, match="closed"):
        export_run(service.store, run["id"], tmp_path / "refused", archive=True)
    client.post(f'/api/v1/bus/runs/{run["id"]}/close', json={"confirm_close": True})
    result = export_run(service.store, run["id"], tmp_path / "archive", archive=True)
    assert result["archived"] is True
    assert len(service.bus.messages(run["id"])) == 0
    assert len(service.bus.messages(imported["run_id"])) == 1


@pytest.mark.parametrize("state", ["host-stored", "host-uncertain", "node-stored", "adapter-submitted", "uncertain"])
def test_backup_and_archive_refuse_unresolved_delivery(console, state):
    _, service = console
    records = AgentStore(service.store)
    value = records.new("bus_deliveries", "test", state, {}, state=state)
    records.save("bus_deliveries", value)
    with pytest.raises(ValueError, match="delivery outcomes"):
        backup_database.quiescent(service.store.db)


def test_closed_bus_rows_survive_credential_erasure(console, tmp_path):
    client, service = console
    run = client.post("/api/v1/bus/runs", json={"name": "preserved", "idempotency_key": "preserved-run-000001"}).json()
    destination = tmp_path / "state.sqlite3"
    destination.touch(mode=0o600)
    backup_database.snapshot(service.settings.state_dir / "state.sqlite3", destination)
    backup_database.sanitize(destination, restored=True)
    with backup_database.connect(destination) as db:
        assert db.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
        row = db.execute("SELECT value FROM bus_runs WHERE id=?", (run["id"],)).fetchone()
        assert json.loads(row[0])["id"] == run["id"]
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4


def test_history_refuses_retained_agent_before_terminal_retirement(console):
    _, service = console
    records = AgentStore(service.store)
    value = records.new("agents", "test", "retained", {}, state="stopped")
    records.save("agents", value)
    with pytest.raises(ValueError, match="coding-agent runs"):
        history_state.inspect(service.settings.state_dir)


@pytest.mark.parametrize("change", ["sender", "sequence", "reference", "oversized", "extension"])
def test_import_validation_is_atomic(console, tmp_path, change):
    _, service = console
    first = {"v": 1, "run": "sample", "agent": "worker", "seq": 1, "type": "note", "body": {"text": "Safe"}}
    second = {**first, "seq": 2}
    if change == "sender":
        second["agent"] = "../host"
    if change == "sequence":
        second["seq"] = 1
    if change == "reference":
        second.update(type="answer", body={"re": "absent-1", "text": "No"})
    if change == "oversized":
        second["body"] = {"text": "x" * 8193}
    if change == "extension":
        second["req"] = ["unknown"]
    path = tmp_path / "input.jsonl"
    path.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    path.chmod(0o600)
    with pytest.raises(ValueError):
        import_run(service.store, path)
    assert service.bus.store.all("bus_runs") == []
    assert service.bus.store.all("bus_messages") == []


@pytest.mark.parametrize("count", [1, 64])
def test_closed_run_archive_checkpoints_bounded_batches(console, monkeypatch, tmp_path, count):
    import asyncio

    from conftest import node

    from ficc.bus_archive import archive
    from ficc.errors import Failure
    client, service = console
    service.store.save_node(node())
    run = client.post("/api/v1/bus/runs", json={"name": "archival", "idempotency_key": "archival-run-000001"}).json()
    records = service.agents.store
    for index in range(count):
        value = records.new("agents", "fixture", f"agent-{index}", {}, run_id=run["id"], node_id="node-0",
                            state="stopped", fingerprint=node()["fingerprint"], outbox_acks=[])
        records.save("agents", value)
    client.post(f'/api/v1/bus/runs/{run["id"]}/close', json={"confirm_close": True})
    calls = []
    failed = False
    async def remote(node_id, action, body, check=None):
        nonlocal failed
        assert action == "archive"
        if not failed:
            failed = True
            raise Failure("timeout", "Injected lost archive reply", 504)
        calls.append(body["agent_id"])
        return {"state": "archived", "agent_id": body["agent_id"], "sha256": "f" * 64, "members": 4, "archive": "private-retained-archive"}
    monkeypatch.setattr(service.agents, "remote", remote)
    output = tmp_path / "closed-archive"
    with pytest.raises(Failure):
        asyncio.run(archive(service, run["id"], str(output)))
    assert service.bus.store.get("bus_runs", run["id"])["state"] == "closed"
    async def resume():
        for _ in range(65):
            result = await archive(service, run["id"], str(output))
            if result["archived"]:
                return result
        pytest.fail("Bounded archive did not complete")
    assert asyncio.run(resume())["archived"] is True
    assert len(calls) == len(set(calls)) == count
    saved = json.loads((output / "node-archives.json").read_text())
    assert len(saved) == count
    assert not service.bus.agents(run["id"])
    assert asyncio.run(archive(service, run["id"], str(output)))["archived"] is True
    assert len(calls) == count
