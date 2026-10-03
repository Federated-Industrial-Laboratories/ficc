# SPDX-License-Identifier: Apache-2.0
"""Qualify network ownership, verified transport, interrupted import and archival."""

import copy
import os
import subprocess
from pathlib import Path

import pytest
from state_fixtures import postgres_admin, write_provider
from test_history import acknowledge, controller
from test_state_storage import settings

from ficc import history, state_cli
from ficc.errors import Failure
from ficc.service import Service
from ficc.state_provider import BINDING, StorageFailure
from ficc.store import Store


def attached(tmp_path, config):
    state = tmp_path / "network"
    write_provider(state, config)
    return state, Store(state / "state.sqlite3")


async def test_data_schema_upgrade_preserves_existing_state_and_dataset_recovery(tmp_path, postgres_config):
    from test_datasets import registered

    state = tmp_path / "data-migration"
    write_provider(state, postgres_config)
    service = Service(settings(state))
    service.store.set_setting("migration_marker", {"retained": True})
    service.close()
    # Schema 12 has all previous tables and no data-source or dataset tables.
    with postgres_admin(postgres_config) as connection:
        for table in ("inspection_files", "inspection_runs", "dataset_objects", "dataset_lineage", "dataset_safety",
                      "source_uploads", "source_runs", "source_queries", "source_connections", "datasets"):
            connection.execute("DROP TABLE " + table)
        connection.execute("UPDATE ficc_state_metadata SET value='12' WHERE key='schema'")
    service = Service(settings(state))
    try:
        assert service.store.get_setting("migration_marker", None) == {"retained": True}
        _, actor = service.auth.issue("token")
        folder = tmp_path / "input"
        folder.mkdir()
        (folder / "values.csv").write_bytes(b"value\n41\n")
        root = await service.files.register(str(folder), "Migrated dataset")
        dataset, _ = await registered(service, actor.id, root)
    finally:
        await service.files.close()
        service.close()
    service = Service(settings(state))
    try:
        _, actor = service.auth.issue("token")
        assert service.datasets.get(dataset["id"], actor.id)["manifest_digest"] == dataset["manifest_digest"]
        assert (await service.datasets.read(dataset["id"], 0, actor.id, 0))[1] == b"value\n41\n"
        with postgres_admin(postgres_config) as connection:
            assert connection.execute("SELECT value FROM ficc_state_metadata WHERE key='schema'").fetchone()[0] == "15"
    finally:
        await service.files.close()
        service.close()


@pytest.mark.parametrize("key,value", [("host", "/tmp/socket"), ("host", "@socket"),
    ("host", "database.example,"), ("host", "database.example,second.example"),
    ("hostaddr", ""), ("hostaddr", "127.0.0.1,127.0.0.2")])
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_connection_target_cannot_bypass_tls_before_password_use(tmp_path, postgres_config, monkeypatch, key, value, count):
    import ficc_state_postgresql
    def forbidden(*args):
        pytest.fail("An invalid transport target reached password loading.")
    monkeypatch.setattr(ficc_state_postgresql, "read_private", forbidden)
    for index in range(count):
        invalid = copy.deepcopy(postgres_config)
        invalid["configuration"]["database"] = f"ficc_test_unreached_{index}"
        invalid["configuration"][key] = value.replace("database", f"database-{index}").replace("socket", f"socket-{index}")
        state = tmp_path / f"invalid-{index}"
        write_provider(state, invalid)
        with pytest.raises(ValueError, match="host name|IP address"):
            Store(state / "state.sqlite3")


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_network_database_refuses_second_owner_and_different_local_binding(tmp_path, postgres_config, count):
    state, store = attached(tmp_path, postgres_config)
    candidates = []
    try:
        for index in range(count):
            other = tmp_path / f"other-{index}"
            write_provider(other, postgres_config)
            (other / BINDING).write_bytes((state / BINDING).read_bytes())
            (other / BINDING).chmod(0o600)
            candidates.append(other)
            with pytest.raises(ValueError, match="owns this database"):
                Store(other / "state.sqlite3")
            store.set_setting(f"retained-{index}", {"owner": "first", "value": index})
    finally:
        store.close()
    for index, other in enumerate(candidates):
        (other / BINDING).write_text(f"{index + 256:032x}")
        with pytest.raises(ValueError, match="binding"):
            Store(other / "state.sqlite3")
    reopened = Store(state / "state.sqlite3")
    try:
        for index in range(count):
            assert reopened.get_setting(f"retained-{index}", None) == {"owner": "first", "value": index}
    finally:
        reopened.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_lost_connection_never_reconnects_or_replays_writes(tmp_path, postgres_config, count):
    state, store = attached(tmp_path, postgres_config)
    try:
        for index in range(count):
            store.set_setting(f"control-{index}", {"value": index})
        pid = store.db.execute("SELECT pg_backend_pid()").scalar_one()
        with postgres_admin(postgres_config) as administrator:
            assert administrator.execute("SELECT pg_terminate_backend(%s)", (pid,)).fetchone()[0]
        with pytest.raises(StorageFailure):
            store.set_setting("lost-write", {"must_not_replay": True})
        with pytest.raises(StorageFailure, match="lost"):
            store.get_setting("control-0", None)
        with postgres_admin(postgres_config) as administrator:
            assert administrator.execute("SELECT count(*) FROM pg_stat_activity WHERE application_name='ficc-state'").fetchone()[0] == 0
    finally:
        store.close()
    reopened = Store(state / "state.sqlite3")
    try:
        assert reopened.get_setting("lost-write", None) is None
        for index in range(count):
            assert reopened.get_setting(f"control-{index}", None) == {"value": index}
    finally:
        reopened.close()


@pytest.mark.parametrize("failure", ["hostname", "authority"])
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_network_connection_requires_trusted_certificate_and_hostname(tmp_path, postgres_config, failure, count):
    for index in range(count):
        value = copy.deepcopy(postgres_config)
        if failure == "hostname":
            value["configuration"]["host"] = f"wrong-state-{index}.invalid"
        else:
            ca = tmp_path / f"untrusted-ca-{index}.pem"
            subprocess.run(["openssl", "req", "-new", "-x509", "-newkey", "ed25519", "-nodes", "-days", "1",
                            "-subj", f"/CN=Untrusted State {index}", "-keyout", str(tmp_path / f"unused-{index}.key"),
                            "-out", str(ca)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            value["configuration"]["ca_file"] = str(ca)
        state = tmp_path / f"untrusted-{index}"
        write_provider(state, value)
        with pytest.raises(StorageFailure, match="verified state database connection failed") as result:
            Store(state / "state.sqlite3")
        assert value["configuration"]["database"] not in str(result.value)
    with postgres_admin(postgres_config) as administrator:
        assert administrator.execute("SELECT count(*) FROM pg_tables WHERE schemaname='public'").fetchone()[0] == 0


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_migration_resumes_committed_import_without_replay_or_source_mutation(tmp_path, postgres_config, monkeypatch, count):
    source, destination = tmp_path / "source", tmp_path / "destination"
    service = Service(settings(source))
    token, _ = service.auth.issue("token")
    workspaces = [service.workspaces.create(f"Preserved {index}") for index in range(count)]
    service.close()
    configuration = Path(os.environ["FICC_TEST_POSTGRES"])
    original = Path.unlink
    def interrupt(path, *args, **kwargs):
        if path == destination / "state.sqlite3":
            raise OSError("injected after committed import")
        return original(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", interrupt)
        with pytest.raises(OSError, match="injected"):
            state_cli.migrate(source, configuration, destination, True)
    assert (destination / "state.sqlite3").exists()
    with pytest.raises(ValueError, match="migration"):
        Store(destination / "state.sqlite3")
    with postgres_admin(postgres_config) as administrator:
        before = administrator.execute("SELECT key,value FROM ficc_state_metadata ORDER BY key").fetchall()
    result = state_cli.resume(destination)
    assert result["migrated"] and result["credentials_removed"] and result["members_disabled"]
    assert not (destination / "state.sqlite3").exists()
    with postgres_admin(postgres_config) as administrator:
        assert administrator.execute("SELECT key,value FROM ficc_state_metadata ORDER BY key").fetchall() == before
    restored = Service(settings(destination))
    try:
        assert restored.store.db.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
        assert [restored.workspaces.get(item["id"]) for item in workspaces] == workspaces
    finally:
        restored.close()
    original_service = Service(settings(source))
    try:
        assert original_service.auth.resolve(token)
        assert [original_service.workspaces.get(item["id"]) for item in workspaces] == workspaces
    finally:
        original_service.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_network_archive_holds_ownership_and_resumes_after_commit(tmp_path, postgres_config, monkeypatch, count):
    source, _, _, _ = controller(tmp_path, count)
    destination, output = tmp_path / "network", tmp_path / "archive"
    state_cli.migrate(source, Path(os.environ["FICC_TEST_POSTGRES"]), destination, True)
    service = Service(settings(destination))
    token, _ = service.auth.issue("token")
    old_controller = service.store.get_setting("controller_id", None)
    for node in service.store.nodes():
        node["capabilities"]["history_archive"] = True
        service.store.save_node(node)
    service.close()
    calls = []
    async def archive(transport, node, intent):
        with pytest.raises(ValueError, match="owns this database"):
            Store(destination / "state.sqlite3")
        calls.append(node["id"])
        return await acknowledge(transport, node, intent)
    monkeypatch.setattr(history, "archive_node", archive)
    original = history.state.commit
    def interrupted(*args):
        original(*args)
        raise OSError("injected after history commit")
    with monkeypatch.context() as patch:
        patch.setattr(history.state, "commit", interrupted)
        with pytest.raises(OSError, match="injected"):
            await history.run(destination, output, True)
    assert len(calls) == count
    assert (await history.run(destination, output, True))["archived"]
    assert len(calls) == count
    restored = Service(settings(destination))
    try:
        assert restored.store.get_setting("controller_id", None) != old_controller
        assert len(restored.store.nodes()) == count
        for table in ("operations", "file_operations", "transfers", "terminals", "credentials"):
            assert restored.store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        with pytest.raises(Failure):
            restored.auth.resolve(token)
    finally:
        restored.close()
