# SPDX-License-Identifier: Apache-2.0
"""Preserve contributor records while removing backup and expired authority."""

import json
import sqlite3

import pytest
from contributor_fixtures import enrollment, heartbeat
from identity_fixtures import legacy_schema
from state_fixtures import postgres_admin, postgres_configuration

from ficc import backup_database, contributor_store
from ficc.errors import Failure
from ficc.state_provider import CONFIG
from ficc.store import Store


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_backup_removes_invites_receipts_and_certificates(contributor_console, tmp_path, count):
    f = contributor_console
    nodes = [enrollment(f, index) for index in range(count)]
    destination = tmp_path / "backup.sqlite3"
    db = f.service.store.db
    if hasattr(db, "snapshot"):
        db.snapshot(destination)
    else:
        with sqlite3.connect(destination) as target:
            db.backup(target)
    backup_database.sanitize(destination)
    recovered = backup_database.connect(destination)
    try:
        backup_database.schema(recovered)
        for table in ("contributor_invitations", "contributor_requests", "contributor_certificates"):
            assert recovered.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        saved = {row[0]: json.loads(row[1]) for row in recovered.execute("SELECT id,value FROM contributors")}
        for node in nodes:
            assert saved[node["node_id"]]["disabled"] is True
            assert saved[node["node_id"]]["revision"] >= 3
    finally:
        recovered.close()
    data = destination.read_bytes()
    for node in nodes:
        assert node["claimed"]["receipt"].encode() not in data
        assert node["invitation"]["secret"].encode() not in data
    # Sanitizing the copied state must not revoke the live source.
    for index, node in enumerate(nodes):
        assert f.client.post("/api/v1/node-channel/poll", headers=f.peer(node["fingerprint"], index),
                             json=heartbeat(index)).status_code == 200


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_node_schema_upgrade_rolls_back_partial_changes(storage_state, monkeypatch, count):
    store = Store(storage_state / "state.sqlite3")
    for index in range(count):
        store.set_setting(f"node-preserve-{index}", {"index": index})
    postgres = (storage_state / CONFIG).exists()
    if not postgres:
        legacy_schema(store.db, 10)
        store.db.commit()
    store.close()
    if postgres:
        with postgres_admin(postgres_configuration()) as db:
            for table in ("contributor_certificates", "contributor_requests", "contributor_invitations", "contributors"):
                db.execute(f"DROP TABLE {table}")
            db.execute("UPDATE ficc_state_metadata SET value='10' WHERE key='schema'")
    with monkeypatch.context() as patch:
        if postgres:
            import ficc_state_postgresql.schema as schema
            def fail():
                raise ValueError("injected node migration failure")
            patch.setattr(schema, "metadata", fail)
        else:
            original = contributor_store.initialize
            def fail(db):
                original(db)
                raise ValueError("injected node migration failure")
            patch.setattr(contributor_store, "initialize", fail)
        with pytest.raises(ValueError, match="injected"):
            Store(storage_state / "state.sqlite3")
    recovered = Store(storage_state / "state.sqlite3")
    try:
        assert recovered.db.execute("SELECT count(*) FROM contributors").fetchone()[0] == 0
        for index in range(count):
            assert recovered.get_setting(f"node-preserve-{index}", None) == {"index": index}
    finally:
        recovered.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_disabled_projects_refuse_live_node_authority(contributor_console, count):
    f = contributor_console
    nodes = [enrollment(f, index) for index in range(count)]
    for index, node in enumerate(nodes):
        assert f.client.post("/api/v1/node-channel/poll", headers=f.peer(node["fingerprint"], index),
                             json=heartbeat(index)).status_code == 200
    # The local recovery project is deliberately never disabled by its public API.
    # Move these synthetic node records to a distinct project before disabling it.
    project = f.service.auth.identities.create("project", "Retired node project")
    with f.service.store.lock, f.service.store.db:
        for node in nodes:
            saved = f.service.contributors.records.get("contributors", node["node_id"])
            saved["project_id"] = project["id"]
            f.service.store.db.execute("UPDATE contributors SET project_id=:p0,value=:p1 WHERE id=:p2",
                                      (project["id"], json.dumps(saved), node["node_id"]))
    for node in nodes:
        f.service.contributors.records.authenticate(node["fingerprint"])
    f.service.auth.identities.update("project", project["id"], project["label"], True, project["revision"])
    for index, node in enumerate(nodes):
        with pytest.raises(Failure):
            f.service.contributors.records.authenticate(node["fingerprint"])
        response = f.client.post("/api/v1/node-channel/poll", headers=f.peer(node["fingerprint"], index), json=heartbeat(index))
        assert response.status_code == 403
