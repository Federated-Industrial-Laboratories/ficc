# SPDX-License-Identifier: Apache-2.0
"""Verify storage exhaustion and capacity refusal preserve accepted work."""

import json
import os
import sqlite3
import subprocess
import sys

import pytest
from conftest import node
from test_files import files_fixture as files_fixture
from test_jobs import manual_poll as manual_poll
from test_jobs import prepare
from test_jobs import request as job_request
from test_terminals import request as terminal_request
from test_transfers import admitted

from ficc.errors import Failure
from ficc.store import Store


@pytest.mark.parametrize("count", [1, 64])
def test_full_database_refuses_job_before_acceptance(console, monkeypatch, count):
    client, service, remote, _ = prepare(console, monkeypatch, count)
    body = job_request(count)
    body["job"]["argv"] += [str(index) + "x" * 4000 for index in range(6)]
    preview = client.post("/api/v1/operation-previews", json=body)
    assert preview.status_code == 200, preview.text
    with service.store.lock:
        db = service.store.db
        db.execute("CREATE TABLE capacity_fixture (payload BLOB)")
        db.commit()
        pages = db.execute("PRAGMA page_count").fetchone()[0]
        db.execute(f"PRAGMA max_page_count={pages + 8}")
        with pytest.raises(sqlite3.OperationalError, match="full"):
            while True:
                db.execute("INSERT INTO capacity_fixture VALUES (zeroblob(3000))")
                db.commit()
        db.rollback()
    try:
        response = client.post("/api/v1/operations", json={"preview_id": preview.json()["preview_id"]},
                               headers={"Idempotency-Key": "capacity-storage-full"})
        assert response.status_code == 503, response.text
        assert response.json()["error"]["code"] == "storage_unavailable"
        assert service.jobs.store.all() == []
        assert not any(value["action"] == "job.submit" for _, value in remote.calls)
    finally:
        with service.store.lock:
            db.execute("PRAGMA max_page_count=2147483646")
            db.execute("DROP TABLE capacity_fixture")
            db.commit()
    retry = client.post("/api/v1/operations", json={"preview_id": preview.json()["preview_id"]},
                        headers={"Idempotency-Key": "capacity-storage-full"})
    assert retry.status_code == 202, retry.text
    assert len(retry.json()["targets"]) == count
    assert len(service.jobs.store.all()) == 1


async def test_transfer_slots_released_only_after_explicit_cleanup(files_fixture):
    service, actor, root, _ = files_fixture
    sources = [{"name": f"pending-{index:02}", "size": index + 1} for index in range(64)]
    operation, preview = await admitted(service, actor, sources, root, "upload")
    before = service.transfers.store.get(operation["id"])
    with pytest.raises(Failure, match="quota"):
        await admitted(service, actor, [{"name": "overflow", "size": 1}], root, "upload")
    assert service.transfers.store.get(operation["id"]) == before
    retry = await service.transfers.submit(preview["preview_id"], operation["key"], actor)
    assert retry["id"] == operation["id"] and len(retry["items"]) == 64
    first = operation["items"][0]
    await service.transfers.change(operation["id"], [first["id"]], actor, discard=True)
    after = service.transfers.store.get(operation["id"])
    assert after["items"][0]["state"] == "cancelled"
    assert after["items"][1:] == before["items"][1:]
    replacement, _ = await admitted(service, actor, [{"name": "replacement", "size": 1}], root, "upload")
    assert len(replacement["items"]) == 1
    with pytest.raises(Failure, match="quota"):
        await admitted(service, actor, [{"name": "overflow-again", "size": 1}], root, "upload")


async def test_transfer_byte_reservations_include_uncertain_items(files_fixture):
    service, actor, root, _ = files_fixture
    operation, _ = await admitted(service, actor, [
        {"name": f"large-{index}", "size": 16 * 1024**3} for index in range(4)
    ], root, "upload")
    changed = service.transfers.store.get(operation["id"])
    changed["items"][0]["state"] = "unknown"
    service.transfers.store.save(changed)
    with pytest.raises(Failure, match="quota"):
        await admitted(service, actor, [{"name": "one-byte", "size": 1}], root, "upload")
    assert service.transfers.store.get(operation["id"])["items"][0]["state"] == "unknown"


def test_terminal_node_and_global_limits_preserve_records(console):
    client, service = console
    for index in range(5):
        service.store.save_node(node(index))
    accepted = []
    for index in range(4):
        for slot in range(4):
            request = terminal_request(index, idempotency_key=f"terminal-limit-{index}-{slot}")
            result = client.post("/api/v1/terminals", json=request)
            assert result.status_code == 200, result.text
            accepted.append(result.json())
        denied = client.post("/api/v1/terminals", json=terminal_request(index, idempotency_key=f"terminal-overflow-{index}"))
        assert denied.status_code == 409
    before = service.terminals.all()
    denied = client.post("/api/v1/terminals", json=terminal_request(4))
    assert denied.status_code == 409
    assert service.terminals.all() == before
    stopped = client.post(f"/api/v1/terminals/{accepted[0]['id']}/stop", json={"confirm_stop": True})
    assert stopped.json()["state"] == "stopped"
    result = client.post("/api/v1/terminals", json=terminal_request(4))
    assert result.status_code == 200
    assert len(service.terminals.all()) == 17
    assert service.terminals.get(accepted[0]["id"])["state"] == "stopped"


@pytest.mark.parametrize("count", [1, 64])
def test_abrupt_exit_recovers_committed_wal_only(tmp_path, count):
    path = tmp_path / "state" / "state.sqlite3"
    program = """
import json, os, sys
from pathlib import Path
from ficc.store import Store
s = Store(Path(sys.argv[1]))
s.db.execute('PRAGMA wal_autocheckpoint=0')
for i in range(int(sys.argv[2])):
    s.set_setting('retained-' + str(i), {'index': i, 'payload': str(i) * 200})
s.db.execute('BEGIN IMMEDIATE')
s.db.execute('UPDATE settings SET value=? WHERE key=?', (json.dumps('uncommitted'), 'retained-0'))
os._exit(23)
"""
    result = subprocess.run([sys.executable, "-c", program, str(path), str(count)],
                            env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}, timeout=15)
    assert result.returncode == 23
    assert path.with_name(path.name + "-wal").stat().st_size > 0
    store = Store(path)
    try:
        assert store.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        values = {row[0]: json.loads(row[1]) for row in store.db.execute(
            "SELECT key,value FROM settings WHERE key LIKE 'retained-%'")}
        assert values == {f"retained-{index}": {"index": index, "payload": str(index) * 200}
                          for index in range(count)}
    finally:
        store.close()
