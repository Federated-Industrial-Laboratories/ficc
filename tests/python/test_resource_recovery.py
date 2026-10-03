# SPDX-License-Identifier: Apache-2.0
"""Qualify durable ownership migration and rollback on both controller databases."""

import json
import secrets

import pytest
from identity_fixtures import legacy_schema
from state_fixtures import postgres_admin, postgres_configuration
from test_backup import populated
from test_identity_projects import member

from ficc import backup_database, resource_store
from ficc.auth import Auth
from ficc.backup import export, restore
from ficc.errors import Failure
from ficc.identity_store import LOCAL_OWNER, LOCAL_PROJECT
from ficc.resource_store import OWNED_TABLES
from ficc.service import Service
from ficc.settings import Settings
from ficc.state_provider import CONFIG
from ficc.store import Store


def prior_state(state, count):
    store = Store(state / "state.sqlite3")
    store.set_setting("controller_id", secrets.token_hex(16))
    actor = Auth(store).issue("token")[1].id
    saved = {}
    with store.db:
        for table in sorted(OWNED_TABLES):
            for index in range(count):
                value = {"id": f"{index + 100:032x}", "actor": actor, "key": f"legacy-{index}",
                         "label": f"Preserved {table} {index}", "state": "stopped" if table == "terminals" else "succeeded",
                         "kind": "upload", "items": [{"id": f"{index + 200:032x}", "state": "succeeded"}],
                         "targets": [{"node_id": f"machine-{index}", "state": "succeeded"}]}
                fields = backup_database.TABLES[table][0].split()
                data = {"id": value["id"], "actor": actor, "key": value["key"], "digest": f"{index + 1:064x}",
                        "value": json.dumps(value), "subject_id": LOCAL_OWNER, "project_id": LOCAL_PROJECT}
                store.db.execute(f"INSERT INTO {table} ({','.join(fields)}) VALUES ({','.join(':p'+str(i) for i in range(len(fields)))})",
                                  tuple(data[name] for name in fields))
                saved[table, value["id"]] = data["value"]
        store.db.execute("DELETE FROM credentials")
    if not (state / CONFIG).exists():
        legacy_schema(store.db, 7)
        store.db.commit()
    store.close()
    if (state / CONFIG).exists():
        with postgres_admin(postgres_configuration()) as db:
            for table in ("external_identities", "policy_bindings", "policy_packages", "policy_publishers"):
                db.execute(f"DROP TABLE {table}")
            db.execute("DROP TABLE project_resources")
            for table in sorted(OWNED_TABLES):
                db.execute(f"ALTER TABLE {table} DROP COLUMN subject_id, DROP COLUMN project_id")
            db.execute("UPDATE ficc_state_metadata SET value='7' WHERE key='schema'")
    return saved


def assert_prior_schema(state):
    if (state / CONFIG).exists():
        with postgres_admin(postgres_configuration()) as db:
            assert db.execute("SELECT value FROM ficc_state_metadata WHERE key='schema'").fetchone()[0] == "7"
            assert not db.execute("SELECT 1 FROM information_schema.columns WHERE table_schema='public' "
                                  "AND table_name='operations' AND column_name='subject_id'").fetchall()
    else:
        db = backup_database.connect(state / "state.sqlite3", readonly=True)
        try:
            assert backup_database.version(db) == 7
            assert "subject_id" not in {row[1] for row in db.execute("PRAGMA table_info(operations)")}
        finally:
            db.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_resource_migration_and_portable_restore_preserve_legacy_owners(storage_state, tmp_path, count):
    saved = prior_state(storage_state, count)
    assert_prior_schema(storage_state)
    store = Store(storage_state / "state.sqlite3")
    try:
        for (table, identity), value in saved.items():
            row = store.db.execute(f"SELECT value,subject_id,project_id FROM {table} WHERE id=:p0", (identity,)).fetchone()
            assert tuple(row) == (value, LOCAL_OWNER, LOCAL_PROJECT)
    finally:
        store.close()
    bundle = tmp_path / "backup"
    assert export(storage_state, bundle)["schema"] == backup_database.SCHEMA
    destination = tmp_path / "restored"
    restore(bundle, destination, confirm_remote_idle=True)
    restored = Store(destination / "state.sqlite3")
    try:
        for (table, identity), value in saved.items():
            assert tuple(restored.db.execute(f"SELECT value,subject_id,project_id FROM {table} WHERE id=:p0",
                                             (identity,)).fetchone()) == (value, LOCAL_OWNER, LOCAL_PROJECT)
    finally:
        restored.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_failed_resource_migration_rolls_back_all_schema_and_data(storage_state, monkeypatch, count):
    saved = prior_state(storage_state, count)
    if (storage_state / CONFIG).exists():
        import ficc_state_postgresql.schema as schema
        def fail_metadata():
            raise ValueError("injected schema interruption")
        with monkeypatch.context() as patch:
            patch.setattr(schema, "metadata", fail_metadata)
            with pytest.raises(ValueError, match="injected"):
                Store(storage_state / "state.sqlite3")
    else:
        initialize = resource_store.initialize
        def fail_initialize(db):
            initialize(db)
            raise ValueError("injected schema interruption")
        with monkeypatch.context() as patch:
            patch.setattr(resource_store, "initialize", fail_initialize)
            with pytest.raises(ValueError, match="injected"):
                Store(storage_state / "state.sqlite3")
    assert_prior_schema(storage_state)
    recovered = Store(storage_state / "state.sqlite3")
    try:
        for (table, identity), value in saved.items():
            assert recovered.db.execute(f"SELECT value FROM {table} WHERE id=:p0", (identity,)).fetchone()[0] == value
    finally:
        recovered.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_resource_restore_preserves_distinct_grants_and_private_owners(storage_state, tmp_path, count):
    service, _, _ = populated(storage_state, count)
    saved = []
    try:
        outside_user, outside_project, _, _ = member(service, "Outside project")
        for index in range(count):
            user, project, _, _ = member(service, f"Resource owner {index}")
            colleague, _, _, _ = member(service, f"Project colleague {index}", project)
            assigned = service.auth.resources.save(project["id"], [f"node-{index}"], [f"{index:032x}"], 0)
            terminal = service.terminals.get(f"terminal-{index}")
            terminal.update(node_id=f"node-{index}", fingerprint=service.store.node(f"node-{index}")["fingerprint"])
            service.terminals.save(terminal)
            with service.store.db:
                for table, prefix in (("operations", "job"), ("file_operations", "mutation"),
                                      ("transfers", "transfer"), ("terminals", "terminal")):
                    service.store.db.execute(f"UPDATE {table} SET subject_id=:p0,project_id=:p1 WHERE id=:p2",
                                             (user["id"], project["id"], f"{prefix}-{index}"))
            saved.append((user, project, colleague, assigned))
        ownership = {table: [tuple(row) for row in service.store.db.execute(
            f"SELECT id,subject_id,project_id FROM {table} ORDER BY id")] for table in sorted(OWNED_TABLES)}
        assert all(len(rows) == count for rows in ownership.values())
    finally:
        service.close()
    bundle, target = tmp_path / "backup", tmp_path / "restored"
    assert export(storage_state, bundle)["schema"] == backup_database.SCHEMA
    restore(bundle, target, confirm_remote_idle=True)
    recovered = Service(Settings(state_dir=target, control=False))
    try:
        for table, expected in ownership.items():
            assert [tuple(row) for row in recovered.store.db.execute(
                f"SELECT id,subject_id,project_id FROM {table} ORDER BY id")] == expected
        assert recovered.store.db.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
        for identity in recovered.auth.identities.users():
            if identity["id"] != LOCAL_OWNER:
                assert identity["disabled"] is True
                recovered.auth.identities.update("user", identity["id"], identity["label"], False, identity["revision"])
        _, outside = recovered.auth.issue("token", subject_id=outside_user["id"], project_id=outside_project["id"])
        for index, (user, project, colleague, assigned) in enumerate(saved):
            assert recovered.auth.resources.get(project["id"]) == assigned
            _, actor = recovered.auth.issue("token", subject_id=user["id"], project_id=project["id"])
            _, shared = recovered.auth.issue("token", subject_id=colleague["id"], project_id=project["id"])
            actor.require("files:read", f"node-{index}", f"{index:032x}")
            assert actor.effective("nodes") == [f"node-{index}"]
            assert actor.effective("roots") == [f"{index:032x}"]
            assert [value["id"] for value in recovered.jobs.store.all(project_id=project["id"])] == [f"job-{index}"]
            for store, prefix in ((recovered.jobs.store, "job"), (recovered.files.store, "mutation"),
                                  (recovered.transfers.store, "transfer")):
                value = store.get(f"{prefix}-{index}")
                assert recovered.auth.record(actor.id, value).id == actor.id
                assert recovered.auth.record(shared.id, value).id == shared.id
                with pytest.raises(Failure) as denied:
                    recovered.auth.record(outside.id, value)
                assert denied.value.status == 404
            for store, prefix in ((recovered.files.store, "mutation"), (recovered.transfers.store, "transfer")):
                assert [value["id"] for value in store.iterate(project_id=project["id"])] == [f"{prefix}-{index}"]
            terminal = recovered.terminals.get(f"terminal-{index}")
            assert recovered.terminals.check(actor.id, "terminals:read", terminal).id == actor.id
            assert [value["id"] for value in recovered.terminals.all(
                project_id=project["id"], subject_id=user["id"])] == [f"terminal-{index}"]
            assert recovered.terminals.all(project_id=project["id"], subject_id=colleague["id"]) == []
            for other in (shared, outside):
                with pytest.raises(Failure) as denied:
                    recovered.terminals.check(other.id, "terminals:read", terminal)
                assert denied.value.status == 404
        assert recovered.jobs.store.all(project_id=outside_project["id"]) == []
        assert list(recovered.files.store.iterate(project_id=outside_project["id"])) == []
        assert list(recovered.transfers.store.iterate(project_id=outside_project["id"])) == []
        assert recovered.terminals.all(project_id=outside_project["id"]) == []
    finally:
        recovered.close()
