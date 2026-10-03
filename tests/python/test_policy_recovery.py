# SPDX-License-Identifier: Apache-2.0
"""Preserve signed policy records and keep restored authority suspended on both databases."""

import hashlib
import json

import pytest
from identity_fixtures import legacy_schema
from policy_fixtures import configure_policy
from state_fixtures import postgres_admin, postgres_configuration
from test_identity_projects import member

from ficc import policy_store
from ficc.backup import export, restore
from ficc.backup_database import SCHEMA
from ficc.errors import Failure
from ficc.service import Service
from ficc.settings import Settings
from ficc.state_provider import CONFIG
from ficc.store import Store


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_policy_restart_and_portable_restore_keep_distinct_roles(storage_state, policy_material, tmp_path, count):
    configure_policy(storage_state)
    settings = Settings(state_dir=storage_state, control=False)
    service = Service(settings)
    records, packages = [], []
    try:
        _, owner = service.auth.issue("token")
        host = service.policies
        host.records.trust("example-publisher", policy_material["public_key"], True, 0)
        for preset in ("managed", "contribution"):
            value = host.install(policy_material[preset], owner.id)
            packages.append(value["digest"])
        for index in range(count):
            user, project, actor, headers = member(service, f"Policy restore {index}", scopes=["workspaces:read", "workspaces:write"])
            role = "observer" if index % 2 else "operator"
            binding = host.records.bind(project["id"], user["id"], [role], 0)
            space = service.workspaces.scoped(actor).create(f"Preserved policy project {index}")
            records.append((user, project, headers["Authorization"][7:], binding, space))
        state = host.activate(packages[0], host.records.state()["revision"], owner.id)
    finally:
        service.close()
    reopened = Service(settings)
    try:
        assert reopened.policies.status()["ready"]
        assert reopened.policies.records.state() == state
        for user, project, token, binding, space in records:
            actor = reopened.auth.resolve(token)
            actor.require("workspaces:read")
            assert reopened.policies.records.bindings(project["id"]) == [binding]
            assert reopened.workspaces.scoped(actor).get(space["id"]) == space
            if binding["roles"] == ["observer"]:
                with pytest.raises(Failure) as denied:
                    actor.require("workspaces:write")
                assert denied.value.code == "policy_denied"
            else:
                actor.require("workspaces:write")
    finally:
        reopened.close()
    bundle, destination = tmp_path / "backup", tmp_path / "restore"
    assert export(storage_state, bundle)["schema"] == SCHEMA
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert "policy-provider.json" not in manifest["members"]
    restore(bundle, destination, confirm_remote_idle=True)
    assert not (destination / "policy-provider.json").exists()
    restored = Service(Settings(state_dir=destination, control=False))
    try:
        host = restored.policies
        status = host.status()
        assert status["required"] and not status["ready"] and status["active"] is None
        assert status["revision"] > state["revision"]
        assert status["history"] == state["history"]
        assert all(not value["enabled"] for value in host.records.publishers())
        assert restored.store.db.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
        for row in restored.store.db.execute("SELECT digest,archive FROM policy_packages"):
            assert hashlib.sha256(row[1]).hexdigest() == row[0]
            assert row[1] in (policy_material["managed"], policy_material["contribution"])
        _, owner = restored.auth.issue("token")
        assert host.owner(owner.id).local_owner
        for user, project, token, binding, space in records:
            assert host.records.bindings(project["id"]) == [binding]
            assert restored.auth.identities.user(user["id"])["disabled"]
            with pytest.raises(Failure):
                restored.auth.resolve(token)
            value = restored.auth.identities.user(user["id"])
            restored.auth.identities.update("user", user["id"], value["label"], False, value["revision"])
            _, actor = restored.auth.issue("token", subject_id=user["id"], project_id=project["id"])
            with pytest.raises(Failure) as denied:
                actor.require("workspaces:read")
            assert denied.value.code == "policy_unavailable"
            assert restored.workspaces.scoped(actor).get(space["id"]) == space
    finally:
        restored.close()
    configure_policy(destination)
    recovered = Service(Settings(state_dir=destination, control=False))
    try:
        _, owner = recovered.auth.issue("token")
        host = recovered.policies
        publisher = host.records.publishers()[0]
        host.records.trust(publisher["id"], publisher["public_key"], True, publisher["revision"])
        host.activate(packages[0], host.records.state()["revision"], owner.id)
        for user, project, _, _, _ in records:
            _, actor = recovered.auth.issue("token", subject_id=user["id"], project_id=project["id"])
            actor.require("workspaces:read")
    finally:
        recovered.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_policy_schema_upgrade_is_atomic(storage_state, monkeypatch, count):
    store = Store(storage_state / "state.sqlite3")
    for index in range(count):
        store.set_setting(f"preserve-{index}", {"index": index})
    postgres = (storage_state / CONFIG).exists()
    if not postgres:
        legacy_schema(store.db, 8)
        store.db.commit()
    store.close()
    if postgres:
        with postgres_admin(postgres_configuration()) as db:
            for table in ("external_identities", "policy_bindings", "policy_packages", "policy_publishers"):
                db.execute(f"DROP TABLE {table}")
            db.execute("UPDATE ficc_state_metadata SET value='8' WHERE key='schema'")
    with monkeypatch.context() as patch:
        if postgres:
            import ficc_state_postgresql.schema as schema
            def fail():
                raise ValueError("injected policy migration failure")
            patch.setattr(schema, "metadata", fail)
        else:
            original = policy_store.initialize
            def fail(db):
                original(db)
                raise ValueError("injected policy migration failure")
            patch.setattr(policy_store, "initialize", fail)
        with pytest.raises(ValueError, match="injected"):
            Store(storage_state / "state.sqlite3")
    if postgres:
        with postgres_admin(postgres_configuration()) as db:
            assert db.execute("SELECT value FROM ficc_state_metadata WHERE key='schema'").fetchone()[0] == "8"
            assert not db.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'policy_%'").fetchall()
    else:
        from ficc.backup_database import connect
        db = connect(storage_state / "state.sqlite3", readonly=True)
        try:
            assert db.execute("PRAGMA user_version").fetchone()[0] == 8
            assert not db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'policy_%'").fetchall()
        finally:
            db.close()
    recovered = Store(storage_state / "state.sqlite3")
    try:
        for index in range(count):
            assert recovered.get_setting(f"preserve-{index}", None) == {"index": index}
        assert policy_store.PolicyStore(recovered).state() == policy_store.DEFAULT
    finally:
        recovered.close()
