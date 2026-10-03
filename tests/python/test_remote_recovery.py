# SPDX-License-Identifier: Apache-2.0
"""Preserve approved identity mappings while suspending restored external authority."""

import pytest
from identity_fixtures import legacy_schema
from state_fixtures import postgres_admin, postgres_configuration
from test_identity_projects import member

from ficc import external_identity_store
from ficc.backup import export, restore
from ficc.backup_database import SCHEMA
from ficc.errors import Failure
from ficc.service import Service
from ficc.settings import Settings
from ficc.state_provider import CONFIG
from ficc.store import Store


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_external_mapping_restart_backup_and_restore(storage_state, tmp_path, count):
    settings = Settings(state_dir=storage_state, control=False)
    service = Service(settings)
    mappings = []
    try:
        for index in range(count):
            user, project, _, _ = member(service, f"Recovered remote user {index}", scopes=["workspaces:read"])
            mapping = service.remote_auth.records.save("https://identity.example/realm", f"external-{index}", user["id"], False, 0)
            secret, _ = service.auth.issue("remote", subject_id=user["id"], project_id=project["id"])
            mappings.append((mapping, secret))
    finally:
        service.close()
    reopened = Service(settings)
    try:
        assert reopened.store.db.execute("SELECT count(*) FROM credentials WHERE kind='remote'").fetchone()[0] == 0
        assert sorted(reopened.remote_auth.records.all(), key=lambda item: item["external_subject"]) == sorted(
            [item[0] for item in mappings], key=lambda item: item["external_subject"])
        for _, secret in mappings:
            with pytest.raises(Failure):
                reopened.auth.resolve(secret)
    finally:
        reopened.close()
    bundle, destination = tmp_path / "backup", tmp_path / "restored"
    assert export(storage_state, bundle)["schema"] == SCHEMA
    restore(bundle, destination, confirm_remote_idle=True)
    restored = Service(Settings(state_dir=destination, control=False))
    try:
        for mapping, secret in mappings:
            current = restored.remote_auth.records.find(mapping["issuer"], mapping["external_subject"])
            assert current == {**mapping, "disabled": True, "revision": mapping["revision"] + 1}
            with pytest.raises(Failure):
                restored.auth.resolve(secret)
        assert restored.remote_auth.provider is None
    finally:
        restored.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_external_mapping_schema_migration_is_atomic(storage_state, monkeypatch, count):
    store = Store(storage_state / "state.sqlite3")
    for index in range(count):
        store.set_setting(f"remote-preserve-{index}", {"index": index})
    postgres = (storage_state / CONFIG).exists()
    if not postgres:
        legacy_schema(store.db, 9)
        store.db.commit()
    store.close()
    if postgres:
        with postgres_admin(postgres_configuration()) as db:
            db.execute("DROP TABLE external_identities")
            db.execute("UPDATE ficc_state_metadata SET value='9' WHERE key='schema'")
    with monkeypatch.context() as patch:
        if postgres:
            import ficc_state_postgresql.schema as schema
            def fail():
                raise ValueError("injected external identity migration failure")
            patch.setattr(schema, "metadata", fail)
        else:
            original = external_identity_store.initialize
            def fail(db):
                original(db)
                raise ValueError("injected external identity migration failure")
            patch.setattr(external_identity_store, "initialize", fail)
        with pytest.raises(ValueError, match="injected"):
            Store(storage_state / "state.sqlite3")
    recovered = Store(storage_state / "state.sqlite3")
    try:
        assert recovered.db.execute("SELECT count(*) FROM external_identities").fetchone()[0] == 0
        for index in range(count):
            assert recovered.get_setting(f"remote-preserve-{index}", None) == {"index": index}
    finally:
        recovered.close()
