# SPDX-License-Identifier: Apache-2.0
"""Qualify module-bound editor reads, retained saves and conflict recovery."""

import copy
import hashlib
import io
import json
import os
import secrets
import zipfile
from pathlib import Path

import pytest
from ficc_node import editor_save

from ficc.errors import Failure
from ficc.module_capabilities import catalogue, validate_instance
from ficc.module_editor_schema import Save
from ficc.module_editor_service import Editor
from ficc.modules import inspect_archive
from ficc.modules.manifest import required_capabilities, validate_manifest
from ficc.service import Service
from ficc.settings import Settings
from ficc.state_provider import BoundConnection
from ficc.workspace_schema import Instance, WorkspaceUpdate

ROOT = Path(__file__).resolve().parents[2]


def install_editor(service, workspace, roots, write=True, manifest=None):
    manifest = manifest or json.loads((ROOT / "modules/file-editor/manifest.json").read_text())
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
    checked = inspect_archive(buffer.getvalue())
    service.modules.install(checked, checked.digest)
    grants = [{"capability": "workspace:read", "target_ids": [workspace["id"]]},
              {"capability": "files:read", "target_ids": [root["id"] for root in roots]}]
    if write:
        grants.append({"capability": "files:write", "target_ids": [root["id"] for root in roots]})
    service.modules.set_enabled(checked.digest, True, grants)
    instance = Instance(id=secrets.token_hex(16), digest=checked.digest, title="Text editor",
                        targets=[root["id"] for root in roots])
    validate_instance(service, workspace["id"], instance)
    service.workspaces.update(workspace["id"], WorkspaceUpdate(revision=workspace["revision"], name=workspace["name"], instances=[instance]))
    return {"workspace_id": workspace["id"], "instance_id": instance.id}, checked.digest, grants


@pytest.fixture
async def editor_fixture(tmp_path):
    service = Service(Settings(state_dir=tmp_path / "state", control=False))
    service.module_editor = Editor(service)
    _, actor = service.auth.issue("token")
    path = tmp_path / "files"
    path.mkdir()
    root = await service.files.register(str(path), "Text files")
    workspace = service.workspaces.create("Work")
    context, package, grants = install_editor(service, workspace, [root])
    try:
        yield service, actor.id, root, path, context, package, grants
    finally:
        await service.files.close()
        await service.transfers.close()
        await service.ssh.close()
        service.close()


async def entries(service, actor, root):
    value = await service.files.listing({"root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"]), "limit": 200}, actor)
    return [{"root_id": root["id"], "entry_id": item["entry_id"]} for item in value["entries"]]


async def read_all(fixture, count=1):
    service, actor, root, path, context, *_ = fixture
    for index in range(count):
        file = path / f"file-{index:02}.txt"
        file.write_text(f"Original {index}\n", encoding="utf-8")
        file.chmod(0o640)
    result = await service.module_editor.read(actor, {**context, "items": await entries(service, actor, root)})
    assert all("data" in item for item in result["results"])
    return result["results"]


def save_body(context, reads):
    return Save.model_validate({**context, "accept_retained_exchange": True, "items": [
        {"root_id": item["root_id"], "entry_id": item["entry_id"], "sha256": item["data"]["sha256"],
         "text": f"Changed {index}\n"} for index, item in enumerate(reads)]}).model_dump()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_real_local_batch_mode_content_idempotency_and_recovery(editor_fixture, count):
    service, actor, root, path, context, *_ = editor_fixture
    reads = await read_all(editor_fixture, count)
    body = save_body(context, reads)
    key = secrets.token_hex(16)
    result = await service.module_editor.save(actor, body, key)
    assert result["state"] == "succeeded", result
    assert len(result["items"]) == count
    before = []
    for index in range(count):
        file = path / f"file-{index:02}.txt"
        assert file.read_text() == f"Changed {index}\n"
        assert file.stat().st_mode & 0o7777 == 0o640
        before.append(file.stat().st_ino)
    repeated = await service.module_editor.save(actor, body, key)
    assert repeated["items"] == result["items"] and repeated["state"] == result["state"]
    assert before == [(path / f"file-{index:02}.txt").stat().st_ino for index in range(count)]
    item = result["items"][0]
    for kind, expected in (("original", "Original 0\n"), ("draft", "Changed 0\n")):
        recovery = await service.module_editor.recovery(actor, {**context, "operation_id": key, "item_id": item["id"], "copy": kind})
        assert recovery["text"] == expected
    result = await service.module_editor.cleanup(actor, {**context, "operation_id": key,
        "item_ids": [item["id"] for item in result["items"]], "confirm": True})
    assert all(not item["retained"] for item in result["items"])
    await service.module_editor.remove(actor, {**context, "operation_id": key})
    assert not service.module_editor.store.all()
    assert not any(item.name.startswith(".ficc-editor-") for item in path.iterdir())


async def test_external_change_refuses_stale_save_without_replacing(editor_fixture):
    service, actor, _, path, context, *_ = editor_fixture
    reads = await read_all(editor_fixture)
    (path / "file-00.txt").write_text("External edit\n")
    result = await service.module_editor.save(actor, save_body(context, reads), secrets.token_hex(16))
    assert result["state"] == "failed" and not result["items"][0]["retained"]
    assert (path / "file-00.txt").read_text() == "External edit\n"


async def test_same_inode_edit_at_exchange_is_retained_as_conflict(editor_fixture, monkeypatch):
    service, actor, _, path, context, *_ = editor_fixture
    reads = await read_all(editor_fixture)
    original = editor_save.rename
    def race(*args):
        (path / "file-00.txt").write_text("Concurrent edit\n")
        return original(*args)
    monkeypatch.setattr(editor_save, "rename", race)
    key = secrets.token_hex(16)
    result = await service.module_editor.save(actor, save_body(context, reads), key)
    assert result["state"] == "conflict" and result["items"][0]["retained"]
    assert (path / "file-00.txt").read_text() == "Changed 0\n"
    item = result["items"][0]
    original = await service.module_editor.recovery(actor, {**context, "operation_id": key, "item_id": item["id"], "copy": "original"})
    assert original["text"] == "Concurrent edit\n"
    with pytest.raises(Failure, match="Recover"):
        await service.module_editor.cleanup(actor, {**context, "operation_id": key, "item_ids": [item["id"]], "confirm": True})
    result = await service.module_editor.cleanup(actor, {**context, "operation_id": key, "item_ids": [item["id"]], "confirm": True, "recovered": True})
    assert not result["items"][0]["retained"] and result["items"][0]["resolved"]


async def test_ack_loss_status_does_not_replay_save(editor_fixture, monkeypatch):
    service, actor, _, path, context, *_ = editor_fixture
    reads = await read_all(editor_fixture)
    original = service.files.transport.call
    async def lost(root, request, *args, **kwargs):
        result = await original(root, request, *args, **kwargs)
        if request["action"] == "editor.save":
            raise Failure("disconnected", "The acknowledgement was lost.", 502)
        return result
    monkeypatch.setattr(service.files.transport, "call", lost)
    key = secrets.token_hex(16)
    result = await service.module_editor.save(actor, save_body(context, reads), key)
    assert result["state"] == "unknown"
    before = (path / "file-00.txt").stat().st_ino
    monkeypatch.setattr(service.files.transport, "call", original)
    service.module_editor = Editor(service)
    result = await service.module_editor.status(actor, {**context, "operation_id": key})
    assert result["state"] == "succeeded" and (path / "file-00.txt").stat().st_ino == before


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "binary", "oversize", "privilege"])
async def test_unsupported_file_modes_and_types_cannot_be_saved(editor_fixture, kind):
    service, actor, root, path, context, *_ = editor_fixture
    file = path / "file.txt"
    file.write_bytes(b"Text")
    if kind == "symlink":
        file.unlink()
        file.symlink_to(path.parent / "outside")
    elif kind == "hardlink":
        os.link(file, path / "other.txt")
    elif kind == "binary":
        file.write_bytes(b"\xff\0")
    elif kind == "oversize":
        file.write_bytes(b"a" * 262145)
    else:
        file.chmod(0o4600)
    results = await service.module_editor.read(actor, {**context, "items": await entries(service, actor, root)})
    assert all("error" in item or item["data"]["writable"] is False for item in results["results"])


async def test_disabled_revoked_target_changes_and_readonly_preview(editor_fixture):
    service, actor, root, path, context, package, grants = editor_fixture
    reads = await read_all(editor_fixture)
    service.modules.set_enabled(package, True, grants[:2])
    preview = await service.module_editor.read(actor, {**context, "items": [{key: reads[0][key] for key in ("root_id", "entry_id")}]})
    assert preview["results"][0]["data"]["writable"] is False
    with pytest.raises(Failure):
        await service.module_editor.save(actor, save_body(context, reads), secrets.token_hex(16))
    service.modules.set_enabled(package, False, [])
    with pytest.raises(Failure):
        await service.module_editor.read(actor, {**context, "items": []})
    service.modules.set_enabled(package, True, grants)
    _, scoped = service.auth.issue("token", scopes=["workspaces:read", "files:read"], root_ids=[root["id"]])
    allowed = await service.module_editor.roots(scoped.id, **context)
    assert allowed["roots"][0]["writable"] is False
    service.auth.revoke(scoped.id)
    with pytest.raises(Failure):
        await service.module_editor.roots(scoped.id, **context)
    workspace = service.workspaces.get(context["workspace_id"])
    workspace["instances"][0]["targets"] = []
    service.workspaces.update(workspace["id"], WorkspaceUpdate(revision=workspace["revision"], name=workspace["name"], instances=workspace["instances"]))
    denied = await service.module_editor.read(actor, {**context, "items": [{key: reads[0][key] for key in ("root_id", "entry_id")}]})
    assert denied["results"][0]["error"]["code"] == "editor_target"
    assert (path / "file-00.txt").read_text() == "Original 0\n"


async def test_readonly_root_is_readable_and_cannot_save(editor_fixture):
    service, actor, root, _, context, *_ = editor_fixture
    reads = await read_all(editor_fixture)
    root["read_only"] = True
    with service.store.lock, service.store.db:
        service.store.db.execute("UPDATE file_roots SET value=? WHERE id=?", (json.dumps(root), root["id"]))
    preview = await service.module_editor.read(actor, {**context, "items": [{key: reads[0][key] for key in ("root_id", "entry_id")}]})
    assert preview["results"][0]["data"]["writable"] is False
    with pytest.raises(Failure, match="read-only"):
        await service.module_editor.save(actor, save_body(context, reads), secrets.token_hex(16))


async def test_capacity_refuses_before_file_publication(editor_fixture, monkeypatch):
    service, actor, _, path, context, *_ = editor_fixture
    reads = await read_all(editor_fixture)
    monkeypatch.setattr(editor_save, "MAX_RETAINED", 1)
    result = await service.module_editor.save(actor, save_body(context, reads), secrets.token_hex(16))
    assert result["state"] == "failed" and (path / "file-00.txt").read_text() == "Original 0\n"
    assert not list(path.glob(".ficc-editor-*"))


def test_editor_optional_write_and_text_limit_counts_utf8_bytes():
    manifest = json.loads((ROOT / "modules/file-editor/manifest.json").read_text())
    assert required_capabilities(manifest) == ["workspace:read", "files:read"]
    with pytest.raises(Failure):
        validate_manifest({**manifest, "optional_capabilities": ["system:read"]})
    with pytest.raises(ValueError):
        Save.model_validate({"workspace_id": "a" * 32, "instance_id": "b" * 32,
            "accept_retained_exchange": True, "items": [{"root_id": "c" * 32, "entry_id": "entry",
                "sha256": hashlib.sha256(b"").hexdigest(), "text": "\u03bb" * 131073}]})


async def test_catalogue_hides_ungranted_folder_and_system_names(editor_fixture):
    service, _, root, _, _, *_ = editor_fixture
    _, actor = service.auth.issue("token", scopes=["modules:manage", "files:read"], root_ids=[root["id"]])
    value = catalogue(service, actor.id)
    assert value["targets"] == {"workspace": [], "system": [], "adapter-profile": [],
        "folder": [{"id": root["id"], "name": "Text files"}]}


async def test_restore_validation_rejects_retained_and_invalid_snapshot(editor_fixture):
    from ficc.module_editor_store import validate_records
    service, actor, root, _, context, *_ = editor_fixture
    reads = await read_all(editor_fixture)
    key = secrets.token_hex(16)
    result = await service.module_editor.save(actor, save_body(context, reads), key)
    validate_records(service.store.db)
    with pytest.raises(ValueError, match="Resolve editor"):
        validate_records(service.store.db, quiescent=True)
    await service.module_editor.cleanup(actor, {**context, "operation_id": key,
        "item_ids": [result["items"][0]["id"]], "confirm": True})
    validate_records(service.store.db, quiescent=True)
    original = service.module_editor.store.get(key)
    for change in ({"workspace_id": "bad"}, {"request_digest": "bad"}, {"extra": "text"},
                   {"state": "unknown"}, {"targets": ["a" * 32]}):
        service.module_editor.store.save({**copy.deepcopy(original), **change})
        with pytest.raises(ValueError):
            validate_records(service.store.db, quiescent=True)
    value = copy.deepcopy(original)
    value["items"][0]["reference"]["parts"] = ["Li4="]
    service.module_editor.store.save(value)
    with pytest.raises(ValueError):
        validate_records(service.store.db)
    service.module_editor.store.save(original)
    service.workspaces.delete(context["workspace_id"], service.workspaces.get(context["workspace_id"])["revision"])
    service.files.store.remove_root(root["id"])
    validate_records(service.store.db, quiescent=True)


async def test_cleanup_ack_loss_is_safe_to_repeat(editor_fixture, monkeypatch):
    from ficc_node import editor as helper
    service, actor, _, _, context, *_ = editor_fixture
    reads = await read_all(editor_fixture)
    key = secrets.token_hex(16)
    result = await service.module_editor.save(actor, save_body(context, reads), key)
    body = {**context, "operation_id": key, "item_ids": [result["items"][0]["id"]], "confirm": True}
    original = helper.save
    def fail_after_removal(base, record):
        if record["retained"] is False:
            raise OSError("Interrupted receipt write")
        return original(base, record)
    monkeypatch.setattr(helper, "save", fail_after_removal)
    with pytest.raises(Failure):
        await service.module_editor.cleanup(actor, body)
    monkeypatch.setattr(helper, "save", original)
    result = await service.module_editor.cleanup(actor, body)
    assert result["items"][0]["retained"] is False


async def test_post_publication_readonly_change_retains_unknown_outcome(editor_fixture, monkeypatch):
    service, actor, root, path, context, *_ = editor_fixture
    reads = await read_all(editor_fixture)
    original = service.files.transport.call
    async def revoke_after(root_value, request, *args, **kwargs):
        result = await original(root_value, request, *args, **kwargs)
        if request["action"] == "editor.save":
            with service.store.lock, service.store.db:
                service.store.db.execute("UPDATE file_roots SET value=? WHERE id=?", (json.dumps({**root, "read_only": True}), root["id"]))
        return result
    monkeypatch.setattr(service.files.transport, "call", revoke_after)
    key = secrets.token_hex(16)
    saved = await service.module_editor.save(actor, save_body(context, reads), key)
    assert saved["state"] == "unknown" and saved["items"][0]["retained"] is True
    assert (path / "file-00.txt").read_text() == "Changed 0\n"
    assert service.module_editor.active(root_id=root["id"])
    checked = await service.module_editor.status(actor, {**context, "operation_id": key})
    assert checked["state"] == "succeeded" and checked["items"][0]["retained"] is True


async def test_intent_before_directory_creation_resolves_without_orphan(editor_fixture, monkeypatch):
    service, actor, root, path, context, *_ = editor_fixture
    reads = await read_all(editor_fixture)
    original = editor_save.os.mkdir
    def stopped(name, *args, **kwargs):
        if isinstance(name, bytes) and name.startswith(b".ficc-editor-"):
            raise RuntimeError("Stopped before staging")
        return original(name, *args, **kwargs)
    monkeypatch.setattr(editor_save.os, "mkdir", stopped)
    key = secrets.token_hex(16)
    with pytest.raises(RuntimeError, match="Stopped before staging"):
        await service.module_editor.save(actor, save_body(context, reads), key)
    monkeypatch.setattr(editor_save.os, "mkdir", original)
    assert service.module_editor.active(root_id=root["id"])
    result = await service.module_editor.status(actor, {**context, "operation_id": key})
    assert result["state"] == "failed" and result["items"][0]["retained"] is False
    assert not service.module_editor.active(root_id=root["id"])
    assert (path / "file-00.txt").read_text() == "Original 0\n"
    await service.module_editor.remove(actor, {**context, "operation_id": key})


async def test_unmeasurable_retained_data_refuses_new_save(editor_fixture, monkeypatch):
    service, actor, _, path, context, *_ = editor_fixture
    reads = await read_all(editor_fixture, 2)
    first = await service.module_editor.save(actor, save_body(context, reads[:1]), secrets.token_hex(16))
    assert first["state"] == "succeeded"
    def unavailable(*_):
        raise OSError("Retained folder unavailable")
    monkeypatch.setattr(editor_save, "stage", unavailable)
    result = await service.module_editor.save(actor, save_body(context, reads[1:]), secrets.token_hex(16))
    assert result["state"] == "failed" and result["items"][0]["retained"] is False
    assert (path / "file-01.txt").read_text() == "Original 1\n"


def test_restore_validation_rejects_excessive_json_depth():
    import sqlite3

    from ficc.module_editor_store import initialize, validate_records
    with sqlite3.connect(":memory:", factory=BoundConnection) as db:
        initialize(db)
        db.execute("CREATE TABLE settings (key TEXT PRIMARY KEY,value TEXT)")
        db.execute("INSERT INTO settings VALUES ('file_reference_key',?)", (json.dumps("a" * 64),))
        db.execute("INSERT INTO module_editor_operations VALUES (?,?,?,?)", ("a" * 32, "b" * 32, "a" * 32, "[" * 1500 + "0" + "]" * 1500))
        with pytest.raises(ValueError):
            validate_records(db, quiescent=True)
