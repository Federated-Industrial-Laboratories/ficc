# SPDX-License-Identifier: Apache-2.0
"""Verify portable stopped-state recovery, identity preservation, and credential erasure."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys

import pytest
from conftest import node

from ficc.auth import digest
from ficc.backup import export, restore
from ficc.errors import Failure
from ficc.service import Service
from ficc.settings import Settings


def populated(path, count=1):
    service = Service(Settings(state_dir=path, control=False))
    credentials, markers = [], []
    controller = service.store.get_setting("controller_id", None)
    (path / "files").mkdir(mode=0o700)
    local = path / "files" / controller
    local.mkdir(mode=0o700, parents=True)
    for index in range(count):
        item = node(index)
        item.update(resources={"cpu_percent": index + 0.5}, state="ready", last_seen=100000000000,
                    capabilities={"resources": True}, boot_id="synthetic-boot", observed_at=1000)
        service.store.save_node(item)
        for kind in ("session", "token", "bootstrap"):
            secret, actor = service.auth.issue(kind, label=f"Fixture {index} {kind}")
            credentials.append(secret)
            markers.extend([secret.encode(), digest(secret).encode(), actor.csrf.encode()])
            if kind == "bootstrap":
                service.auth.revoke(actor.id)
        name = hashlib.sha256(item["key"].encode()).hexdigest()
        key = path / "trust" / name
        if not key.exists():
            key.write_text(f"ficc-pin {item['key_type']} {item['key']}\n")
            key.chmod(0o600)
        root = {"id": f"{index:032x}", "path": f"/synthetic/registered/{index}", "node_id": item["id"],
                "identity": {"dev": 2, "ino": 400 + index}, "reference": {"parts": []}, "label": f"Root {index}"}
        service.files.store.add_root(root)
        operation = {"id": f"job-{index}", "actor": "fixture", "key": f"job-{index}", "digest": f"digest-{index}",
                     "targets": [{"node_id": item["id"], "job_id": f"job-target-{index}", "state": "succeeded"}]}
        service.jobs.store.insert(operation)
        value = {"id": f"mutation-{index}", "actor": "fixture", "key": f"mutation-{index}",
                 "state": "succeeded", "items": [{"state": "succeeded", "id": f"item-{index}"}]}
        service.files.store.insert(value)
        transfer = {**value, "id": f"transfer-{index}", "kind": "upload", "key": f"transfer-{index}"}
        service.transfers.store.insert(transfer)
        service.terminals.save({"id": f"terminal-{index}", "actor": "fixture", "key": f"terminal-{index}",
                                "digest": f"term-digest-{index}", "state": "stopped", "mode": "tmux"})
        receipt = local / f"{index:032x}.json"
        receipt.write_text(json.dumps({"id": receipt.stem, "state": "succeeded", "digest": f"file-digest-{index}"}))
        receipt.chmod(0o600)
    return service, credentials, markers


@pytest.mark.parametrize("count", [1, 64])
def test_roundtrip_preserves_every_identity_and_erases_credential_bytes(tmp_path, count):
    state, bundle, target = (tmp_path / value for value in ("state", "backup", "restored"))
    service, credentials, markers = populated(state, count)
    settings = dict(service.store.db.execute("SELECT key,value FROM settings"))
    rows = {table: service.store.db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
            for table in ("file_roots", "operations", "file_operations", "transfers", "terminals")}
    nodes = service.store.nodes()
    raw_before = (state / "state.sqlite3").read_bytes() + (state / "state.sqlite3-wal").read_bytes()
    assert all(row[0].encode() in raw_before for row in service.store.db.execute("SELECT digest FROM credentials"))
    service.close()
    assert export(state, bundle)["credentials_removed"]
    originals = {str(p.relative_to(bundle)): p.read_bytes() for p in bundle.rglob("*") if p.is_file()}
    assert "manifest.json" in originals and len(originals) == count + 3
    assert not any("-wal" in name or "-journal" in name for name in originals)
    assert all(marker not in data for data in originals.values() for marker in markers)
    with sqlite3.connect(bundle / "state.sqlite3") as db:
        assert db.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert db.execute("PRAGMA freelist_count").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
    assert restore(bundle, target, True)["observations_cleared"]
    assert originals == {str(p.relative_to(bundle)): p.read_bytes() for p in bundle.rglob("*") if p.is_file()}
    assert all(p.stat().st_mode & 0o777 == (0o700 if p.is_dir() else 0o600) for p in target.rglob("*"))
    recovered = Service(Settings(state_dir=target, control=False))
    try:
        assert dict(recovered.store.db.execute("SELECT key,value FROM settings")) == settings
        for table, expected in rows.items():
            assert recovered.store.db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall() == expected
        for expected, actual in zip(nodes, recovered.store.nodes(), strict=True):
            for key in ("id", "profile", "host", "account", "port", "fingerprint", "key", "key_type"):
                assert actual[key] == expected[key]
            assert recovered.view(actual)["stale"] is True
            assert actual["resources"] is None and actual["last_seen"] is None and actual["capabilities"] == {}
        for secret in credentials:
            with pytest.raises(Failure) as denied:
                recovered.auth.resolve(secret, ("token", "session", "bootstrap"))
            assert denied.value.code == "unauthenticated"
        fresh, principal = recovered.auth.issue("token")
        assert recovered.auth.resolve(fresh).id == principal.id
    finally:
        recovered.close()
    assert not list(tmp_path.glob(".ficc-maintenance-*"))


@pytest.mark.parametrize("table,value", [
    ("operations", {"targets": [{"state": "running"}]}),
    ("operations", {"targets": [{"state": "unknown"}]}),
    ("file_operations", {"state": "unknown", "items": [{"state": "unknown"}]}),
    ("file_operations", {"state": "failed", "items": [{"state": "dispatching"}]}),
    ("terminals", {"state": "detached"}),
    ("terminals", {"state": "unknown"}),
    ("transfers", {"kind": "upload", "items": [{"state": "interrupted"}]}),
    ("transfers", {"kind": "copy", "items": [{"state": "unknown"}]}),
    ("transfers", {"kind": "copy", "items": [{"state": "succeeded", "cleanup_pending": True}]}),
    ("transfers", {"kind": "download", "items": [{"state": "succeeded"}]}),
])
def test_activity_refuses_backup_without_changing_state(tmp_path, table, value):
    state, bundle = tmp_path / "state", tmp_path / "bundle"
    service, _, _ = populated(state)
    with service.store.db:
        service.store.db.execute(f"UPDATE {table} SET value=?", (json.dumps(value),))
    service.close()
    before = (state / "state.sqlite3").read_bytes()
    with pytest.raises(ValueError, match="before backup or restore"):
        export(state, bundle)
    assert not bundle.exists() and not list(tmp_path.glob(".ficc-maintenance-*"))
    assert (state / "state.sqlite3").read_bytes() == before


@pytest.mark.parametrize("kind", ["receipt", "download"])
def test_unrecorded_local_objects_block_backup(tmp_path, kind):
    state = tmp_path / "state"
    service, _, _ = populated(state)
    controller = service.store.get_setting("controller_id", None)
    service.close()
    path = state / "downloads" / "retained" if kind == "download" else state / "files" / controller / ("e" * 32 + ".json")
    path.write_text(json.dumps({"id": "e" * 32, "state": "preparing"}))
    path.chmod(0o600)
    with pytest.raises(ValueError):
        export(state, tmp_path / "bundle")


def test_cli_roundtrip_is_usable_and_requires_remote_idle_acknowledgement(tmp_path):
    state, bundle, target = (tmp_path / value for value in ("state", "backup", "restored"))
    service, _, _ = populated(state)
    service.close()
    def cli(*args):
        return subprocess.run([sys.executable, "-m", "ficc.cli", *map(str, args)], capture_output=True, text=True, timeout=15)
    result = cli("backup", "--state-dir", state, "--output", bundle)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["backup"] == str(bundle)
    refused = cli("restore", "--backup", bundle, "--state-dir", target)
    assert refused.returncode == 1 and "--confirm-remote-idle" in refused.stderr and not target.exists()
    result = cli("restore", "--backup", bundle, "--state-dir", target, "--confirm-remote-idle")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["state_dir"] == str(target)
    before = (target / "state.sqlite3").read_bytes()
    repeated = cli("restore", "--backup", bundle, "--state-dir", target, "--confirm-remote-idle")
    assert repeated.returncode == 1 and (target / "state.sqlite3").read_bytes() == before


def test_wal_recovery_includes_committed_state(tmp_path):
    state, bundle = tmp_path / "state", tmp_path / "backup"
    env = dict(os.environ, BACKUP_TEST_STATE=str(state))
    program = '''import os
from pathlib import Path
from ficc.service import Service
from ficc.settings import Settings
s = Service(Settings(state_dir=Path(os.environ["BACKUP_TEST_STATE"]), control=False))
s.store.set_setting("wal_fixture", "committed-without-close")
os._exit(0)
'''
    subprocess.run([sys.executable, "-c", program], env=env, check=True, timeout=10)
    assert (state / "state.sqlite3-wal").stat().st_size > 0
    export(state, bundle)
    with sqlite3.connect(bundle / "state.sqlite3") as db:
        assert json.loads(db.execute("SELECT value FROM settings WHERE key='wal_fixture'").fetchone()[0]) == "committed-without-close"


def test_registered_tree_content_is_excluded(tmp_path):
    state, data = tmp_path / "state", tmp_path / "registered"
    data.mkdir()
    original = b"registered-content-is-not-controller-state"
    (data / "input").write_bytes(original)
    service, _, _ = populated(state)
    with service.store.db:
        service.store.db.execute("UPDATE file_roots SET value=?", (json.dumps({"id": "0" * 32, "path": str(data)}),))
    service.close()
    export(state, tmp_path / "bundle")
    restore(tmp_path / "bundle", tmp_path / "recovered", True)
    assert (data / "input").read_bytes() == original
    assert not any(original in p.read_bytes() for p in (tmp_path / "bundle").rglob("*") if p.is_file())


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("table", ["operations", "file_operations", "transfers", "terminals"])
def test_last_record_and_last_batch_item_blocks_export(tmp_path, count, table):
    state = tmp_path / "state"
    service, _, _ = populated(state, count)
    prefix = {"operations": "job", "file_operations": "mutation", "transfers": "transfer", "terminals": "terminal"}[table]
    operation_id = f"{prefix}-{count - 1}"
    if table == "terminals":
        value = {"id": operation_id, "state": "unknown"}
    elif table == "operations":
        value = {"id": operation_id, "targets": [{"node_id": f"node-{index}", "state": "succeeded"} for index in range(count)]}
        value["targets"][-1]["state"] = "unknown"
    else:
        value = {"id": operation_id, "state": "succeeded", "kind": "upload",
                 "items": [{"id": f"item-{index}", "state": "succeeded"} for index in range(count)]}
        value["items"][-1]["state"] = "unknown"
    with service.store.db:
        service.store.db.execute(f"UPDATE {table} SET value=? WHERE id=?", (json.dumps(value), operation_id))
    service.close()
    with pytest.raises(ValueError, match="before backup or restore"):
        export(state, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()
