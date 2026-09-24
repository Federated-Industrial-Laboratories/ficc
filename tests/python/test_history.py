# SPDX-License-Identifier: Apache-2.0
"""Verify explicit controller epoch archival and resumable commit boundaries."""

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from test_backup import populated

from ficc import history, history_state
from ficc.errors import Failure
from ficc.service import Service
from ficc.settings import Settings


def controller(tmp_path, count=1):
    state = tmp_path / "state"
    service, credentials, markers = populated(state, count)
    old = {key: service.store.get_setting(key, None) for key in ("controller_id", "terminal_controller", "file_reference_key")}
    for node in service.store.nodes():
        node["capabilities"]["history_archive"] = True
        service.store.save_node(node)
    with service.store.db:
        for index in range(count):
            for table, prefix in (("file_operations", "mutation"), ("transfers", "transfer"), ("terminals", "terminal")):
                row = service.store.db.execute(f"SELECT value FROM {table} WHERE id=?", (f"{prefix}-{index}",)).fetchone()
                value = json.loads(row[0])
                if table == "terminals":
                    value["node_id"] = f"node-{index}"
                elif table == "file_operations":
                    value["root"] = {"node_id": f"node-{index}"}
                else:
                    value["items"][0]["destination"] = {"root": {"node_id": f"node-{index}"}}
                service.store.db.execute(f"UPDATE {table} SET value=? WHERE id=?", (json.dumps(value), f"{prefix}-{index}"))
    service.close()
    return state, old, credentials, markers


async def acknowledge(transport, node, intent):
    assert (transport.settings.state_dir / history_state.PENDING).exists()
    assert (Path(intent["output"]) / "controller/manifest.json").exists()
    return {"archive_id": intent["archive_id"], "state": "complete", "path": "/synthetic/archive/" + node["id"],
            "manifest_sha256": "f" * 64, "members": 3, "bytes": 42, "controller_id": intent["controller_id"],
            "next_controller_id": intent["next_controller_id"]}


@pytest.mark.parametrize("count", [1, 64])
async def test_epoch_retirement_preserves_metadata_and_restores_capacity(tmp_path, monkeypatch, count):
    state, old, credentials, markers = controller(tmp_path, count)
    output = tmp_path / "archive"
    calls = []
    async def archive(transport, node, intent):
        calls.append(node["id"])
        return await acknowledge(transport, node, intent)
    monkeypatch.setattr(history, "archive_node", archive)
    preview = await history.run(state, output)
    assert not preview["archived"] and len(preview["preview"]["nodes"]) == count
    assert not output.exists() and not (state / history_state.PENDING).exists() and calls == []
    result = await history.run(state, output, True)
    assert result["archived"] and len(result["node_archives"]) == count
    assert sorted(calls) == sorted(f"node-{index}" for index in range(count))
    assert not (state / history_state.PENDING).exists()
    with sqlite3.connect(output / "controller/state.sqlite3") as db:
        for table in ("operations", "file_operations", "transfers", "terminals", "file_roots", "nodes"):
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == count
    assert all(marker not in path.read_bytes() for path in output.rglob("*") if path.is_file() for marker in markers)
    current = Service(Settings(state_dir=state, control=False))
    try:
        for table in ("operations", "file_operations", "transfers", "terminals", "credentials"):
            assert current.store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        assert len(current.store.nodes()) == count and len(current.files.store.roots()) == count
        assert current.store.get_setting("controller_id", None) != old["controller_id"]
        assert current.store.get_setting("terminal_controller", None) != old["terminal_controller"]
        assert current.store.get_setting("file_reference_key", None) == old["file_reference_key"]
        for secret in credentials:
            with pytest.raises(Failure):
                current.auth.resolve(secret)
        assert all(node["last_seen"] is None and node["resources"] is None for node in current.store.nodes())
        assert not list((state / "files" / old["controller_id"]).glob("*.json"))
        for index in range(count):
            current.jobs.store.insert({"id": f"new-{index}", "actor": "fresh", "key": f"new-key-{index}",
                                       "digest": f"digest-{index}", "targets": [{"node_id": f"node-{index}", "state": "succeeded"}]})
    finally:
        current.close()
    before = len(calls)
    assert (await history.run(state, output, True))["archive_id"] == result["archive_id"]
    assert len(calls) == before


@pytest.mark.parametrize("boundary", ["node_reply", "node_saved", "controller_commit", "receipt_removal", "closure"])
async def test_pending_archive_blocks_start_and_resumes_same_ids(tmp_path, monkeypatch, boundary):
    state, old, _, _ = controller(tmp_path, 2)
    output = tmp_path / "archive"
    observed = []
    async def archive(transport, node, intent):
        observed.append((node["id"], intent["archive_id"], intent["next_controller_id"]))
        value = await acknowledge(transport, node, intent)
        if boundary == "node_reply" and len(observed) == 1:
            raise ValueError("synthetic lost node reply")
        return value
    monkeypatch.setattr(history, "archive_node", archive)
    with monkeypatch.context() as patch:
        if boundary == "controller_commit":
            original = history_state.commit
            def commit(*args):
                original(*args)
                raise OSError("synthetic after commit")
            patch.setattr(history_state, "commit", commit)
        elif boundary == "receipt_removal":
            original = history_state.remove
            def remove(*args):
                original(*args)
                raise OSError("synthetic after receipt removal")
            patch.setattr(history_state, "remove", remove)
        elif boundary in {"node_saved", "closure"}:
            original = history_state.save
            def save(path, value, *args):
                original(path, value, *args)
                if (boundary == "node_saved" and path.name == history_state.PENDING and value.get("acknowledgements")) or (
                        boundary == "closure" and path.name == "archive.json" and value.get("state") == "complete"):
                    raise OSError("synthetic after journal publication")
            patch.setattr(history_state, "save", save)
        with pytest.raises((ValueError, OSError), match="synthetic"):
            await history.run(state, output, True)
    intent = history_state.read(state / history_state.PENDING)
    with pytest.raises(ValueError, match="archive"):
        Service(Settings(state_dir=state))
    result = await history.run(state, output, True)
    assert result["archived"] and result["archive_id"] == intent["archive_id"]
    assert all(item[1:] == (intent["archive_id"], intent["next_controller_id"]) for item in observed)
    assert not (state / history_state.PENDING).exists()
    assert history_state.committed(state, intent)
    assert intent["controller_id"] == old["controller_id"]


@pytest.mark.parametrize("count", [1, 64])
async def test_cli_receipts_are_archived_without_credentials_before_retirement(tmp_path, monkeypatch, count):
    state, _, _, _ = controller(tmp_path, count)
    folder = state / "cli-requests"
    folder.mkdir(mode=0o700)
    expected, secrets = {}, []
    with sqlite3.connect(state / "state.sqlite3") as db:
        for index in range(count):
            key = f"explicit-cli-key-{index:05d}"
            name = hashlib.sha256(key.encode()).hexdigest() + ".json"
            secret = f"synthetic-history-credential-{index}"
            secrets.append(secret.encode())
            value = {"key": key, "digest": f"digest-{index}", "grant": {"id": "fixture", "credential": secret}, "operation_id": f"job-{index}"}
            path = folder / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            db.execute("UPDATE operations SET key=? WHERE id=?", (key, f"job-{index}"))
            expected[name] = {"key": key, "digest": f"digest-{index}", "actor": "fixture", "operation_id": f"job-{index}"}
    monkeypatch.setattr(history, "archive_node", acknowledge)
    output = tmp_path / "archive"
    await history.run(state, output, True)
    for name, receipt in expected.items():
        assert not (folder / name).exists()
        assert json.loads((output / "cli" / name).read_bytes()) == receipt
    assert not any(secret in item.read_bytes() for item in output.rglob("*") if item.is_file() for secret in secrets)


async def test_history_refuses_activity_running_owner_and_missing_helper(tmp_path, monkeypatch):
    state, _, _, _ = controller(tmp_path)
    output = tmp_path / "archive"
    current = Service(Settings(state_dir=state, control=False))
    with pytest.raises(ValueError, match="already uses"):
        await history.run(state, output, True)
    current.close()
    with sqlite3.connect(state / "state.sqlite3") as db:
        db.execute("UPDATE operations SET value=?", (json.dumps({"targets": [{"state": "unknown"}]}),))
    with pytest.raises(ValueError, match="active or unknown"):
        await history.run(state, output, True)
    assert not output.exists() and not (state / history_state.PENDING).exists()


@pytest.mark.parametrize("table", ["operations", "terminals", "file_operations", "transfers"])
@pytest.mark.parametrize("count", [1, 64])
async def test_forgotten_machine_history_cannot_be_silently_retired(tmp_path, table, count):
    state, _, _, _ = controller(tmp_path, count)
    with sqlite3.connect(state / "state.sqlite3") as db:
        identity, raw = db.execute(f"SELECT id,value FROM {table} ORDER BY rowid DESC LIMIT 1").fetchone()
        value = json.loads(raw)
        if table == "operations":
            value["targets"][0]["node_id"] = "forgotten"
        elif table == "terminals":
            value["node_id"] = "forgotten"
        elif table == "file_operations":
            value["root"]["node_id"] = "forgotten"
        else:
            value["items"][0]["destination"]["root"]["node_id"] = "forgotten"
        db.execute(f"UPDATE {table} SET value=? WHERE id=?", (json.dumps(value), identity))
    with pytest.raises(ValueError, match="forgotten machine"):
        await history.run(state, tmp_path / "archive", True)
    assert not (state / history_state.PENDING).exists()
