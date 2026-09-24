# SPDX-License-Identifier: Apache-2.0
"""Detect corrupt bundles, unsafe paths, concurrent owners, and failed publication."""

import errno
import hashlib
import json
import os
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient
from test_backup import populated

from ficc import backup_database as database
from ficc import backup_io as files
from ficc.api import create_app
from ficc.auth import digest
from ficc.backup import export, restore
from ficc.control import Control
from ficc.service import Service
from ficc.settings import Settings
from ficc.state_lock import StateLock


@pytest.fixture
def bundle(tmp_path):
    service, _, _ = populated(tmp_path / "state")
    service.close()
    export(tmp_path / "state", tmp_path / "bundle")
    return tmp_path / "bundle"


def replace_manifest(bundle, transform):
    path = bundle / "manifest.json"
    value = json.loads(path.read_bytes())
    transform(value)
    path.write_text(json.dumps(value))


def rehash(bundle):
    path = bundle / "state.sqlite3"
    replace_manifest(bundle, lambda value: value["members"].update({"state.sqlite3": {
        "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}}))


@pytest.mark.parametrize("change", ["hash", "size", "schema", "identity", "path", "missing", "extra", "link", "hardlink", "mode", "database", "trigger"])
def test_restore_refuses_invalid_bundle_without_destination(tmp_path, bundle, change):
    path = bundle / "state.sqlite3"
    if change == "hash":
        replace_manifest(bundle, lambda value: value["members"]["state.sqlite3"].update(sha256="0" * 64))
    elif change == "size":
        replace_manifest(bundle, lambda value: value["members"]["state.sqlite3"].update(size=files.MAX_DATABASE + 1))
    elif change == "schema":
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA user_version=999")
        rehash(bundle)
    elif change == "identity":
        replace_manifest(bundle, lambda value: value.update(controller_id="a" * 32))
    elif change == "path":
        replace_manifest(bundle, lambda value: value["members"].update({"../escape": {"size": 0, "sha256": "0" * 64}}))
    elif change == "missing":
        path.unlink()
    elif change == "extra":
        (bundle / "unexpected").write_bytes(b"unknown")
        (bundle / "unexpected").chmod(0o600)
    elif change == "link":
        outside = tmp_path / "outside"
        path.rename(outside)
        path.symlink_to(outside)
    elif change == "hardlink":
        os.link(path, tmp_path / "linked")
    elif change == "mode":
        path.chmod(0o644)
    elif change == "database":
        path.write_bytes(b"not a database")
        rehash(bundle)
    else:
        with sqlite3.connect(path) as db:
            db.execute("CREATE TRIGGER unsafe AFTER DELETE ON credentials BEGIN DELETE FROM nodes; END")
        rehash(bundle)
    with pytest.raises((ValueError, OSError, sqlite3.Error)):
        restore(bundle, tmp_path / "target", True)
    assert not (tmp_path / "target").exists() and not list(tmp_path.glob(".ficc-maintenance-*"))


def test_restore_removes_added_credentials_again(tmp_path, bundle):
    token, csrf = "synthetic-restored-token", "synthetic-restored-csrf"
    with sqlite3.connect(bundle / "state.sqlite3") as db:
        db.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?,?)", (
            "synthetic-id", digest(token), "token", "Restore fixture", '["nodes:read"]', "null",
            time.time() + 3600, csrf, "null"))
    rehash(bundle)
    restore(bundle, tmp_path / "target", True)
    raw = (tmp_path / "target/state.sqlite3").read_bytes()
    assert digest(token).encode() not in raw and csrf.encode() not in raw
    with sqlite3.connect(tmp_path / "target/state.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
        assert db.execute("PRAGMA freelist_count").fetchone()[0] == 0


@pytest.mark.parametrize("boundary", ["snapshot", "copy", "manifest", "sync", "publish", "parent_sync", "allocation"])
def test_backup_storage_failure_cleans_staging_and_preserves_source(tmp_path, monkeypatch, boundary):
    state, target = tmp_path / "state", tmp_path / "backup"
    service, _, _ = populated(state)
    service.close()
    before = (state / "state.sqlite3").read_bytes()
    def fail(*args, **kwargs):
        raise OSError(errno.ENOSPC, "synthetic disk full")
    if boundary == "allocation":
        original = files.os.open
        def allocate(path, *args, **kwargs):
            return fail() if isinstance(path, str) and path.startswith(".ficc-maintenance-") else original(path, *args, **kwargs)
        monkeypatch.setattr(files.os, "open", allocate)
    elif boundary == "snapshot":
        monkeypatch.setattr(database, "snapshot", fail)
    elif boundary == "copy":
        monkeypatch.setattr(files, "copy", fail)
    elif boundary == "manifest":
        original = files.write
        def write(fd, name, data):
            return fail() if name == "manifest.json" else original(fd, name, data)
        monkeypatch.setattr(files, "write", write)
    elif boundary == "sync":
        monkeypatch.setattr(files.os, "fsync", fail)
    elif boundary == "publish":
        monkeypatch.setattr(files, "rename", fail)
    else:
        original = files.os.fsync
        inode = tmp_path.stat().st_ino
        def sync(fd):
            return fail() if os.fstat(fd).st_ino == inode else original(fd)
        monkeypatch.setattr(files.os, "fsync", sync)
    with pytest.raises(OSError, match="synthetic disk full"):
        export(state, target)
    assert (state / "state.sqlite3").read_bytes() == before
    assert not target.exists() and not list(tmp_path.glob(".ficc-maintenance-*"))
    with StateLock(state):
        pass


def test_restore_storage_failure_and_publication_race_do_not_clobber(tmp_path, bundle, monkeypatch):
    target = tmp_path / "target"
    def fail(*args):
        raise OSError(errno.ENOSPC, "synthetic disk full")
    with monkeypatch.context() as patch:
        patch.setattr(files, "copy", fail)
        with pytest.raises(OSError, match="synthetic disk full"):
            restore(bundle, target, True)
    assert not target.exists() and not list(tmp_path.glob(".ficc-maintenance-*"))
    original = files.rename
    def race(*args):
        target.mkdir(mode=0o700)
        (target / "owner-file").write_bytes(b"do not replace")
        return original(*args)
    monkeypatch.setattr(files, "rename", race)
    with pytest.raises(FileExistsError):
        restore(bundle, target, True)
    assert (target / "owner-file").read_bytes() == b"do not replace"
    assert not list(tmp_path.glob(".ficc-maintenance-*"))


def test_running_service_and_held_lock_refuse_before_database_access(tmp_path, monkeypatch):
    import ficc.service as service_module
    state = tmp_path / "state"
    service, _, _ = populated(state)
    calls = []
    try:
        def forbidden_store(*args):
            calls.append(args)
            raise AssertionError("The database was opened before exclusive state ownership.")
        monkeypatch.setattr(service_module, "Store", forbidden_store)
        with pytest.raises(ValueError, match="already uses"):
            Service(Settings(state_dir=state))
        assert calls == []
        with pytest.raises(ValueError, match="already uses"):
            export(state, tmp_path / "backup")
        assert not (tmp_path / "backup").exists()
    finally:
        service.close()


@pytest.mark.parametrize("failure", ["schema", "demo", "store"])
def test_constructor_failure_releases_lock(tmp_path, monkeypatch, failure):
    import ficc.service as service_module
    state = tmp_path / "state"
    service = Service(Settings(state_dir=state, demo=True))
    service.close()
    if failure == "schema":
        with sqlite3.connect(state / "state.sqlite3") as db:
            db.execute("PRAGMA user_version=999")
    elif failure == "store":
        def failed_store(*args):
            raise OSError(errno.ENOSPC, "synthetic disk full")
        monkeypatch.setattr(service_module, "Store", failed_store)
    with pytest.raises((ValueError, OSError)):
        Service(Settings(state_dir=state))
    with StateLock(state):
        pass


def test_socket_start_failure_releases_service_lock(tmp_path, monkeypatch):
    state = tmp_path / "state"
    async def fail(*args):
        raise OSError(errno.ENOSPC, "synthetic socket failure")
    monkeypatch.setattr(Control, "start", fail)
    app = create_app(Settings(state_dir=state))
    with pytest.raises(OSError, match="synthetic socket failure"), TestClient(app):
        pass
    with StateLock(state):
        pass


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "mode"])
def test_unsafe_lock_is_refused(tmp_path, kind):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    lock = state / "service.lock"
    outside = tmp_path / "outside"
    outside.write_bytes(b"untouched")
    outside.chmod(0o600)
    if kind == "symlink":
        lock.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, lock)
    else:
        lock.write_bytes(b"")
        lock.chmod(0o644)
    with pytest.raises((ValueError, OSError)):
        StateLock(state)
    assert outside.read_bytes() == b"untouched"
    assert not (state / "state.sqlite3").exists()


def test_backup_refuses_incomplete_schema_and_symlink_parent(tmp_path):
    state = tmp_path / "state"
    service = Service(Settings(state_dir=state))
    service.close()
    link = tmp_path / "link"
    link.symlink_to(state, target_is_directory=True)
    with pytest.raises(OSError):
        export(link, tmp_path / "bundle")
    with sqlite3.connect(state / "state.sqlite3") as db:
        db.execute("DROP TABLE transfers")
    with pytest.raises(ValueError, match="incomplete"):
        export(state, tmp_path / "bundle")


def test_created_member_directories_are_synced_before_publication(tmp_path, monkeypatch):
    target = tmp_path / "target"
    synced = set()
    original = os.fsync
    def sync(fd):
        synced.add(os.readlink(f"/proc/self/fd/{fd}"))
        original(fd)
    monkeypatch.setattr(files.os, "fsync", sync)
    with files.staging(target) as (fd, path):
        files.write(fd, "files/" + "a" * 32 + "/" + "b" * 32 + ".json", b"{}")
        stage = os.readlink(str(path))
        assert stage in synced
        assert stage + "/files" in synced
        assert stage + "/files/" + "a" * 32 in synced
    assert target.is_dir()


def test_backup_and_restore_refuse_nested_destinations_with_parent_components(tmp_path, bundle):
    state = tmp_path / "state"
    alias = tmp_path / "unused" / ".." / "state" / "inside"
    with pytest.raises(ValueError, match="outside"):
        export(state, alias)
    alias = tmp_path / "unused" / ".." / "bundle" / "inside"
    with pytest.raises(ValueError, match="outside"):
        restore(bundle, alias, True)
    assert not (state / "inside").exists() and not (bundle / "inside").exists()
