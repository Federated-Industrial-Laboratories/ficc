# SPDX-License-Identifier: Apache-2.0
"""Verify workspace recovery, package integrity and removal of restored execution grants."""

import hashlib
import json
import os
import sqlite3

import pytest
from test_modules_packages import bundle, package

from ficc.backup import export, restore
from ficc.backup_database import LEGACY_TABLES, MODULE_TABLES, SCHEMA, TABLES
from ficc.errors import Failure
from ficc.history_state import digest
from ficc.modules import archive, inspect_archive
from ficc.service import Service
from ficc.settings import Settings
from ficc.workspace_schema import SurfaceUpdate, ViewUpdate, WorkspaceUpdate


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("restart", [False, True])
def test_interrupted_install_recovers_before_backup(tmp_path, count, restart):
    state = tmp_path / "state"
    retained = inspect_archive(bundle(*package({"keep.txt": b"Keep this installed file."})))
    service = Service(Settings(state_dir=state, control=False))
    service.modules.install(retained, retained.digest)
    service.close()
    inspection = inspect_archive(bundle(*package({f"data/item-{i}.txt": str(i).encode()
                                                  for i in range(count)})))
    child = os.fork()
    if child == 0:
        service = Service(Settings(state_dir=state, control=False))

        def interrupted(*args, **kwargs):
            os._exit(77)

        archive.os.rename = interrupted
        service.modules.install(inspection, inspection.digest)
        os._exit(99)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 77
    assert len(list((state / "modules").glob(".stage-*"))) == 1
    if restart:
        reopened = Service(Settings(state_dir=state, control=False))
        assert [item["digest"] for item in reopened.modules.list()] == [retained.digest]
        reopened.close()
    assert export(state, tmp_path / "before-reinstall")["members"] == 3
    assert not list((state / "modules").glob(".stage-*"))
    reopened = Service(Settings(state_dir=state, control=False))
    try:
        assert (reopened.modules.verify(retained.digest) / "keep.txt").read_bytes() == b"Keep this installed file."
        reopened.modules.install(inspection, inspection.digest)
        assert reopened.modules.verify(inspection.digest)
    finally:
        reopened.close()
    assert export(state, tmp_path / "after-reinstall")["members"] == count + 4


@pytest.mark.parametrize("kind", ["stage-link", "member-link"])
def test_stage_recovery_never_follows_links(tmp_path, kind):
    root = tmp_path / "modules"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    target = outside / "retained.txt"
    target.write_text("Retain this file.")
    stage = root / ".stage-abcdefgh"
    if kind == "stage-link":
        stage.symlink_to(outside, target_is_directory=True)
    else:
        stage.mkdir(mode=0o700)
        (stage / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(Failure):
        archive.recover_stages(root)
    assert target.read_text() == "Retain this file."


def populate(path, count=1):
    service = Service(Settings(state_dir=path, control=False))
    inspection = inspect_archive(bundle(*package({"bin/player": b"native fixture"},
        runtime={"kind": "native", "language": "c", "entry": "bin/player",
                 "platform": "linux", "architecture": "x86_64"}, capabilities=["workspace:read"])))
    installed = service.modules.install(inspection, inspection.digest)
    spaces = []
    for index in range(count):
        value = service.workspaces.create(f"Workspace {index}")
        value = service.workspaces.update(value["id"], WorkspaceUpdate(revision=0, name=value["name"],
            instances=[{"id": f"{index:032x}", "digest": installed["digest"], "title": "Note",
                        "state": {"editor": f"Saved text {index}"}}]))
        view = f"{index + 128:032x}"
        service.workspaces.save_view(value["id"], view, ViewUpdate(revision=0, layout={}))
        service.workspaces.save_surface(f"{index + 256:032x}", SurfaceUpdate(revision=0,
            tiles=[{"id": f"{index + 512:032x}", "workspace_id": value["id"], "view_id": view}], layout={}))
        spaces.append(value)
    service.modules.set_enabled(installed["digest"], True,
        [{"capability": "workspace:read", "target_ids": [space["id"] for space in spaces]}], sandbox_ready=True)
    return service, installed["digest"], spaces


@pytest.mark.parametrize("count", [1, 64])
def test_workspace_and_native_module_roundtrip(tmp_path, count):
    state, bundle_path, target = (tmp_path / name for name in ("state", "backup", "restored"))
    service, checksum, spaces = populate(state, count)
    before = digest(service.store.db)
    assert len(before) == 64
    original = service.modules.get(checksum)
    service.close()
    assert export(state, bundle_path)["schema"] == SCHEMA
    assert restore(bundle_path, target, True)["module_grants_removed"]
    recovered = Service(Settings(state_dir=target, control=False))
    try:
        assert recovered.workspaces.all() == sorted(spaces, key=lambda value: value["id"])
        current = recovered.modules.get(checksum)
        assert current["manifest"] == original["manifest"]
        assert not current["enabled"] and current["grants"] == []
        assert current["revision"] > original["revision"]
        directory = recovered.modules.verify(checksum)
        assert (directory / "bin/player").stat().st_mode & 0o777 == 0o500
        assert (directory / "manifest.json").stat().st_mode & 0o777 == 0o400
        assert (directory / "bin").stat().st_mode & 0o777 == 0o500
    finally:
        recovered.close()


@pytest.mark.parametrize("case", ["content", "manifest", "extra", "link", "missing"])
def test_export_refuses_inconsistent_payloads(tmp_path, case):
    state = tmp_path / "state"
    service, checksum, _ = populate(state)
    directory = service.modules.root / checksum
    service.close()
    (directory / "bin").chmod(0o700)
    directory.chmod(0o700)
    if case == "content":
        (directory / "bin/player").chmod(0o600)
        (directory / "bin/player").write_bytes(b"changed")
    elif case == "manifest":
        (directory / "manifest.json").chmod(0o600)
        (directory / "manifest.json").write_text("{}")
    elif case == "extra":
        (directory / "extra").write_bytes(b"extra")
        (directory / "extra").chmod(0o600)
    elif case == "missing":
        (directory / "bin/player").unlink()
    else:
        os.link(directory / "bin/player", directory / "linked")
    with pytest.raises(ValueError):
        export(state, tmp_path / "backup")
    assert not (tmp_path / "backup").exists()
    assert not list(tmp_path.glob(".ficc-maintenance-*"))


def test_restore_refuses_payload_tampering_even_with_rehashed_outer_manifest(tmp_path):
    state = tmp_path / "state"
    service, checksum, _ = populate(state)
    service.close()
    archive = tmp_path / "backup"
    export(state, archive)
    member = f"modules/{checksum}/bin/player"
    (archive / member).write_bytes(b"substitution")
    manifest = json.loads((archive / "manifest.json").read_text())
    manifest["members"][member] = {"size": 12, "sha256": hashlib.sha256(b"substitution").hexdigest()}
    (archive / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="digest"):
        restore(archive, tmp_path / "restored", True)
    assert not (tmp_path / "restored").exists()


def test_legacy_backup_restores_and_migrates_on_open(tmp_path):
    state, archive, target = (tmp_path / name for name in ("state", "backup", "restored"))
    service = Service(Settings(state_dir=state, control=False))
    service.close()
    with sqlite3.connect(state / "state.sqlite3") as db:
        for table in set(TABLES) - set(LEGACY_TABLES):
            db.execute(f"DROP TABLE {table}")
        db.execute("PRAGMA user_version=4")
    assert export(state, archive)["schema"] == 4
    assert restore(archive, target, True)["schema"] == 4
    recovered = Service(Settings(state_dir=target, control=False))
    try:
        assert recovered.store.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA
        assert recovered.workspaces.all() == [] and recovered.modules.list() == []
    finally:
        recovered.close()


def test_previous_module_schema_keeps_payloads_and_migrates(tmp_path):
    state, archive, target = (tmp_path / name for name in ("state", "backup", "restored"))
    service, checksum, spaces = populate(state)
    service.close()
    with sqlite3.connect(state / "state.sqlite3") as db:
        for table in set(TABLES) - set(MODULE_TABLES):
            db.execute(f"DROP TABLE {table}")
        db.execute("PRAGMA user_version=5")
    assert export(state, archive)["schema"] == 5
    assert restore(archive, target, True)["schema"] == 5
    recovered = Service(Settings(state_dir=target, control=False))
    try:
        assert recovered.store.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA
        assert recovered.workspaces.all() == spaces
        package = recovered.modules.get(checksum)
        assert not package["enabled"] and package["grants"] == []
        recovered.modules.verify(checksum)
        assert recovered.windows.records.all() == [] and recovered.adapters.records.profiles() == []
    finally:
        recovered.close()
