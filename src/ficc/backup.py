# SPDX-License-Identifier: Apache-2.0
"""Export stopped controller state and restore verified bundles into new directories."""

import hashlib
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from . import __version__, backup_cli
from . import backup_database as database
from . import backup_io as files
from .state_lock import StateLock


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("A backup JSON object has duplicate fields.")
        value[key] = item
    return value


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise ValueError("The backup contains invalid JSON.") from None


def receipt(root, name, controller):
    if not name.startswith("files/"):
        return
    if name.split("/")[1] != controller:
        raise ValueError("A local file receipt belongs to another controller.")
    value = decode(files.read(root, name, 262144))
    if (not isinstance(value, dict) or value.get("id") != Path(name).stem
            or value.get("state") not in {"succeeded", "cancelled"} or value.get("cleanup_pending")):
        raise ValueError("Resolve all active or unknown local file receipts before backup or restore.")


def describe(root, name):
    digest = hashlib.sha256()
    size = 0
    with files.member(root, name) as fd:
        while data := os.read(fd, 262144):
            size += len(data)
            if size > files.limit(name):
                raise ValueError("A backup member exceeds its size limit.")
            digest.update(data)
    return {"size": size, "sha256": digest.hexdigest()}


def capacity(root, names):
    total = 0
    for name in names:
        with files.member(root, name) as fd:
            total += os.fstat(fd).st_size
        if total > files.MAX_TOTAL:
            raise ValueError("The backup exceeds the total size limit.")


def export(state_dir: Path, destination: Path):
    with files.directory(state_dir), StateLock(state_dir) as ownership:
        return export_locked(state_dir, destination, ownership)


def export_locked(state_dir: Path, destination: Path, ownership: StateLock, maintenance=False):
    state_dir, destination = Path(os.path.abspath(state_dir)), Path(os.path.abspath(destination))
    if destination.is_relative_to(state_dir):
        raise ValueError("Store the backup outside the controller state directory.")
    with files.directory(state_dir) as source:
        if ownership.fd is None:
            raise ValueError("The backup requires current state ownership.")
        owned = os.fstat(ownership.fd)
        actual = os.stat("service.lock", dir_fd=source, follow_symlinks=False)
        if (owned.st_dev, owned.st_ino) != (actual.st_dev, actual.st_ino):
            raise ValueError("The backup ownership belongs to another state directory.")
        names = files.inventory(source, maintenance=maintenance)
        capacity(source, names)
        database_path = Path(f"/proc/self/fd/{source}/state.sqlite3")
        with closing(database.connect(database_path, readonly=True)) as db:
            controller = database.quiescent(db)
            backup_cli.reconciled(source, db, decode)
        for name in names:
            receipt(source, name, controller)
        with files.staging(destination) as (target, folder):
            files.write(target, "state.sqlite3", b"")
            database.snapshot(database_path, folder / "state.sqlite3")
            database.sanitize(folder / "state.sqlite3")
            members = {"state.sqlite3": describe(target, "state.sqlite3")}
            with files.member(target, "state.sqlite3") as fd:
                os.fsync(fd)
            for name in names:
                if name != "state.sqlite3":
                    members[name] = files.copy(source, target, name)
            if sum(value["size"] for value in members.values()) > files.MAX_TOTAL:
                raise ValueError("The backup exceeds the total size limit.")
            manifest = {"format": "ficc-state", "format_version": 1, "application_version": __version__,
                        "schema": database.SCHEMA, "created_at": int(time.time()), "controller_id": controller,
                        "members": members}
            raw = files.encode(manifest)
            if len(raw) > files.MAX_MANIFEST:
                raise ValueError("The backup manifest exceeds the size limit.")
            files.write(target, "manifest.json", raw)
    return {"backup": str(destination), "members": len(members), "schema": database.SCHEMA,
            "credentials_removed": True}


def manifest(source):
    value = decode(files.read(source, "manifest.json", files.MAX_MANIFEST))
    fields = {"format", "format_version", "application_version", "schema", "created_at", "controller_id", "members"}
    if (not isinstance(value, dict) or set(value) != fields or value["format"] != "ficc-state"
            or type(value["format_version"]) is not int or value["format_version"] != 1
            or type(value["schema"]) is not int or value["schema"] != database.SCHEMA
            or not isinstance(value["application_version"], str) or not 1 <= len(value["application_version"]) <= 80
            or type(value["created_at"]) is not int or value["created_at"] < 0
            or not isinstance(value["controller_id"], str) or not re.fullmatch(files.HEX32, value["controller_id"])
            or not isinstance(value["members"], dict) or not 1 <= len(value["members"]) <= files.MAX_MEMBERS):
        raise ValueError("The backup manifest format or schema is not supported.")
    total = 0
    for name, detail in value["members"].items():
        maximum = files.limit(name)
        if (not isinstance(detail, dict) or set(detail) != {"size", "sha256"}
                or type(detail["size"]) is not int or not 0 <= detail["size"] <= maximum
                or not isinstance(detail["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", detail["sha256"])):
            raise ValueError("A backup member descriptor is invalid.")
        total += detail["size"]
    if total > files.MAX_TOTAL or files.inventory(source, bundle=True) != sorted(value["members"]):
        raise ValueError("The backup member set or total size is invalid.")
    return value


def restore(bundle: Path, destination: Path, confirm_remote_idle=False):
    if confirm_remote_idle is not True:
        raise ValueError("Check that remote work since this backup is idle, then pass --confirm-remote-idle.")
    bundle, destination = Path(os.path.abspath(bundle)), Path(os.path.abspath(destination))
    if destination.is_relative_to(bundle):
        raise ValueError("Restore outside the backup directory.")
    with files.directory(bundle) as source:
        value = manifest(source)
        with files.staging(destination) as (target, folder):
            for name, expected in value["members"].items():
                actual = files.copy(source, target, name)
                if actual != expected:
                    raise ValueError("A backup member size or SHA-256 digest does not match.")
                receipt(target, name, value["controller_id"])
            controller = database.sanitize(folder / "state.sqlite3", restored=True)
            if controller != value["controller_id"]:
                raise ValueError("The manifest and database controller identities do not match.")
            with files.member(target, "state.sqlite3") as fd:
                os.fsync(fd)
    return {"state_dir": str(destination.absolute()), "schema": database.SCHEMA,
            "credentials_removed": True, "observations_cleared": True}


def add_commands(commands):
    from .settings import default_state_dir
    backup = commands.add_parser("backup", help="Export stopped, quiescent controller state.")
    backup.add_argument("--state-dir", type=Path, default=default_state_dir())
    backup.add_argument("--output", type=Path, required=True)
    recover = commands.add_parser("restore", help="Verify a backup and create a new private state directory.")
    recover.add_argument("--backup", type=Path, required=True)
    recover.add_argument("--state-dir", type=Path, required=True)
    recover.add_argument("--confirm-remote-idle", action="store_true",
                         help="Confirm remote work since the backup was checked and is idle.")


def execute(args):
    try:
        result = export(args.state_dir, args.output) if args.command == "backup" else restore(
            args.backup, args.state_dir, args.confirm_remote_idle)
    except sqlite3.Error:
        raise ValueError("The state database could not be verified or copied. Check its integrity and free storage.") from None
    print(json.dumps(result, indent=2))
