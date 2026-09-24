# SPDX-License-Identifier: Apache-2.0
"""Bind archived controller state and retire only verified closed local receipts."""

import hashlib
import json
import os
import re
import time
from contextlib import closing
from pathlib import Path

from ficc_node import history_write

from . import backup, backup_cli
from . import backup_database as database
from . import backup_io as files

PENDING = "archive.pending.json"
MAX_INTENT = 1024 * 1024


def read(path, maximum=MAX_INTENT):
    with files.directory(path.parent) as folder:
        return backup.decode(files.read(folder, path.name, maximum))


def save(path, value, maximum=MAX_INTENT):
    if len(files.encode(value)) > maximum:
        raise ValueError("The history state exceeds its size limit.")
    with files.directory(path.parent):
        history_write.write(path, value, maximum)


def digest(db):
    result = hashlib.sha256()
    for table in sorted(database.TABLES):
        result.update(table.encode() + b"\n")
        for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid"):
            result.update(json.dumps(row, allow_nan=False, separators=(",", ":")).encode() + b"\n")
    return result.hexdigest()


def enrolled_history(db, nodes):
    enrolled = {node["id"] for node in nodes}
    def check(node_id, local=False):
        if node_id is None and local:
            return
        if node_id not in enrolled:
            raise ValueError("Retained history names a forgotten machine. Reconcile its original enrollment and remote history before archival.")
    for operation in database.records(db, "operations"):
        for target in operation["targets"]:
            check(target.get("node_id"))
    for terminal in database.records(db, "terminals"):
        check(terminal.get("node_id"))
    for operation in database.records(db, "file_operations"):
        root = operation.get("root")
        if not isinstance(root, dict):
            raise ValueError("A file operation has no retained root identity.")
        check(root.get("node_id"), local=True)
    for operation in database.records(db, "transfers"):
        for item in operation["items"]:
            for name in ("destination", "source"):
                endpoint = item.get(name)
                if endpoint is None and name == "source" and operation["kind"] == "upload":
                    continue
                if not isinstance(endpoint, dict) or not isinstance(endpoint.get("root"), dict):
                    raise ValueError("A transfer has no retained endpoint identity.")
                check(endpoint["root"].get("node_id"), local=True)


def inspect(state):
    with files.directory(state) as folder, closing(database.connect(state / "state.sqlite3", readonly=True)) as db:
        controller = database.quiescent(db)
        if db.execute("SELECT count(*) FROM agents").fetchone()[0]:
            raise ValueError("Export and archive retained coding-agent runs before retiring terminal history.")
        backup_cli.reconciled(folder, db, backup.decode)
        names = files.inventory(folder, maintenance=True)
        for name in names:
            backup.receipt(folder, name, controller)
        settings = dict(db.execute("SELECT key,value FROM settings"))
        terminal = json.loads(settings["terminal_controller"])
        if not isinstance(terminal, str) or not re.fullmatch(files.HEX32, terminal):
            raise ValueError("The terminal controller identity is invalid.")
        nodes = list(database.records(db, "nodes"))
        enrolled_history(db, nodes)
        counts = {table: db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                  for table in ("operations", "file_operations", "transfers", "terminals")}
        preview = {"counts": counts, "nodes": [{key: node[key] for key in
                   ("id", "name", "profile", "host", "account", "fingerprint")} for node in nodes]}
        return {"controller_id": controller, "terminal_controller": terminal, "nodes": nodes,
                "database_sha256": digest(db), "preview": preview}


def verify_backup(path, expected=None):
    with files.directory(path) as folder:
        value = backup.manifest(folder)
        for name, detail in value["members"].items():
            if backup.describe(folder, name) != detail:
                raise ValueError("The history backup member hash changed.")
        detail = hashlib.sha256(files.read(folder, "manifest.json", files.MAX_MANIFEST)).hexdigest()
    if expected and detail != expected:
        raise ValueError("The history backup manifest changed.")
    return value, detail


def local_receipts(state, output, manifest):
    path = output / "retirement.json"
    if path.exists() or path.is_symlink():
        value = read(path, files.MAX_MANIFEST)
        return value, hashlib.sha256(files.encode(value)).hexdigest()
    value = {"format": 1, "files": {name: detail for name, detail in manifest["members"].items() if name.startswith("files/")}, "cli": {}}
    with files.directory(state) as source, files.directory(output) as target, closing(database.connect(state / "state.sqlite3", readonly=True)) as db:
        if (state / "cli-requests").exists():
            for name in sorted(os.listdir(state / "cli-requests")):
                if name == "requests.lock":
                    continue
                source_name = "cli-requests/" + name
                raw = files.read(source, source_name, 65536)
                saved = backup.decode(raw)
                operation = db.execute("SELECT id FROM operations WHERE actor=? AND key=?", (saved["grant"]["id"], saved["key"])).fetchone()
                if operation is None:
                    raise ValueError("The CLI receipt no longer has a retained operation.")
                sanitized = files.encode({"key": saved["key"], "digest": saved["digest"], "actor": saved["grant"]["id"], "operation_id": operation[0]})
                archive_name = "cli/" + name
                try:
                    os.mkdir("cli", 0o700, dir_fd=target)
                except FileExistsError:
                    pass
                with files.directory(output / "cli"):
                    history_write.persist(output / "cli", output)
                    history_write.recover(output / archive_name, 65536)
                if (output / archive_name).exists():
                    if files.read(target, archive_name, 65536) != sanitized:
                        raise ValueError("An archived CLI receipt changed.")
                else:
                    history_write.write_bytes(output / archive_name, sanitized, 65536)
                value["cli"][source_name] = {"source": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                                             "archive": archive_name, "sha256": hashlib.sha256(sanitized).hexdigest()}
    save(path, value, files.MAX_MANIFEST)
    return value, hashlib.sha256(files.encode(value)).hexdigest()


def committed(state, intent):
    with closing(database.connect(state / "state.sqlite3", readonly=True)) as db:
        values = dict(db.execute("SELECT key,value FROM settings"))
        return all(json.loads(values.get(key, "null")) == expected for key, expected in (
            ("controller_id", intent["next_controller_id"]), ("terminal_controller", intent["next_terminal_controller"]),
            ("last_archive_id", intent["archive_id"])))


def commit(state, intent):
    if committed(state, intent):
        return
    with closing(database.connect(state / "state.sqlite3")) as db:
        database.quiescent(db)
        if digest(db) != intent["database_sha256"]:
            raise ValueError("Controller state changed after the history archive intent.")
        with db:
            for table in ("operations", "file_operations", "transfers", "terminals", "credentials"):
                db.execute(f"DELETE FROM {table}")
            for key, value in (("controller_id", intent["next_controller_id"]),
                               ("terminal_controller", intent["next_terminal_controller"]), ("last_archive_id", intent["archive_id"])):
                db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, json.dumps(value)))
            for node in database.records(db, "nodes"):
                node.update(resources=None, last_seen=None, capabilities={}, state="unconfigured",
                            error={"code": "history_archived", "message": "Refresh this machine after history archival."})
                node.pop("observed_at", None)
                node.pop("boot_id", None)
                db.execute("UPDATE nodes SET value=? WHERE id=?", (json.dumps(node), node["id"]))
            db.execute("INSERT INTO audit(at,action,target,outcome,actor) VALUES (?,?,?,?,?)",
                       (time.time(), "history.archive", intent["archive_id"], "success", "local-owner"))
            db.execute("DELETE FROM audit WHERE id <= (SELECT max(id)-10000 FROM audit)")
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def retire(state, output, value):
    with files.directory(state) as source, files.directory(output) as target:
        for name, detail in value["files"].items():
            files.limit(name)
            with files.directory(output / "controller") as archive:
                if backup.describe(archive, name) != detail:
                    raise ValueError("An archived local file receipt changed.")
            remove(source, name, detail, 262144)
        for name, detail in value["cli"].items():
            if not re.fullmatch(r"cli-requests/[a-f0-9]{64}\.json", name):
                raise ValueError("The local receipt retirement path is invalid.")
            if detail["archive"] != "cli/" + Path(name).name:
                raise ValueError("The archived CLI receipt path is invalid.")
            raw = files.read(target, detail["archive"], 65536)
            if hashlib.sha256(raw).hexdigest() != detail["sha256"]:
                raise ValueError("An archived CLI receipt changed.")
            remove(source, name, detail["source"], 65536)


def remove(root, name, expected, maximum):
    try:
        raw = files.read(root, name, maximum)
    except FileNotFoundError:
        return
    if {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} != expected:
        raise ValueError("A local receipt changed after archival; it was retained.")
    parts = name.split("/")
    folder = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
            os.close(folder)
            folder = child
        os.unlink(parts[-1], dir_fd=folder)
        os.fsync(folder)
    finally:
        os.close(folder)
