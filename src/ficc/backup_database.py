# SPDX-License-Identifier: Apache-2.0
"""Validate quiescent schema-three snapshots and remove credential storage."""

import json
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from ficc_node.job_spec import TERMINAL as JOB_TERMINAL

from .backup_io import MAX_DATABASE

SCHEMA = 3
TABLES = {
    "nodes": ("id value", 64),
    "credentials": ("id digest kind label scopes nodes expires csrf roots", 512),
    "audit": ("id at action target outcome actor", 10000),
    "settings": ("key value", 64),
    "operations": ("id actor key digest value", 2048),
    "file_roots": ("id value", 64),
    "file_operations": ("id actor key value", 2048),
    "transfers": ("id actor key value", 2048),
    "terminals": ("id actor key digest value", 512),
    "sqlite_sequence": ("name seq", 1),
}


def connect(path: Path, readonly=False):
    suffix = "?mode=ro" if readonly else "?mode=rw"
    db = sqlite3.connect(path.absolute().as_uri() + suffix, uri=True, timeout=1)
    db.execute("PRAGMA trusted_schema=OFF")
    deadline = time.monotonic() + 60
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
    return db


def records(db, table):
    for row in db.execute(f"SELECT value FROM {table}"):
        if not isinstance(row[0], str) or len(row[0]) > 1024 * 1024:
            raise ValueError("A state record exceeds the backup limit.")
        try:
            value = json.loads(row[0])
        except RecursionError:
            raise ValueError("A state record exceeds the nesting limit.") from None
        if not isinstance(value, dict):
            raise ValueError("A state record is invalid.")
        yield value


def schema(db):
    if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA:
        raise ValueError("Backup and restore require the current state schema.")
    objects = db.execute("SELECT type,name,sql FROM sqlite_schema").fetchall()
    names = set()
    for kind, name, sql in objects:
        if kind == "index" and sql is None and name.startswith("sqlite_autoindex_"):
            continue
        if kind != "table" or name not in TABLES or "CREATE VIRTUAL" in (sql or "").upper():
            raise ValueError("The database contains an unsupported schema object.")
        names.add(name)
        columns = [row[1] for row in db.execute(f"PRAGMA table_info({name})")]
        if columns != TABLES[name][0].split():
            raise ValueError("The database table layout is not supported.")
        if db.execute(f"SELECT count(*) FROM {name}").fetchone()[0] > TABLES[name][1]:
            raise ValueError("The retained state exceeds its supported capacity.")
    if names != set(TABLES):
        raise ValueError("The database schema is incomplete.")
    if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("The database integrity check failed.")


def quiescent(db):
    schema(db)
    for node in records(db, "nodes"):
        if not isinstance(node.get("id"), str):
            raise ValueError("A machine record identity is invalid.")
    for operation in records(db, "operations"):
        targets = operation.get("targets")
        if (not isinstance(targets, list) or not 1 <= len(targets) <= 64
                or any(not isinstance(target, dict) or target.get("state") not in JOB_TERMINAL for target in targets)):
            raise ValueError("Resolve all active or unknown jobs before backup or restore.")
    for terminal in records(db, "terminals"):
        if terminal.get("state") not in {"exited", "interrupted", "stopped"}:
            raise ValueError("Stop or reconcile all terminal sessions before backup or restore.")
    for operation in records(db, "file_operations"):
        items = operation.get("items")
        if (operation.get("state") not in {"succeeded", "failed"} or not isinstance(items, list)
                or not 1 <= len(items) <= 64 or any(not isinstance(item, dict)
                or item.get("state") not in {"succeeded", "failed"} for item in items)):
            raise ValueError("Resolve all active or unknown file operations before backup or restore.")
    for operation in records(db, "transfers"):
        items = operation.get("items")
        if (operation.get("kind") not in {"upload", "download", "copy"} or not isinstance(items, list)
                or not 1 <= len(items) <= 64 or any(not isinstance(item, dict)
                or item.get("state") not in {"succeeded", "cancelled"} or item.get("cleanup_pending")
                or (operation["kind"] == "download" and item["state"] == "succeeded") for item in items)):
            raise ValueError("Finish or discard transfers, prepared downloads, and retained partials before backup or restore.")
    settings = dict(db.execute("SELECT key,value FROM settings"))
    controller = json.loads(settings.get("controller_id", "null"))
    if not isinstance(controller, str) or not re.fullmatch(r"[a-f0-9]{32}", controller):
        raise ValueError("The controller identity is missing or invalid.")
    return controller


def snapshot(source: Path, destination: Path):
    deadline = time.monotonic() + 60
    page_size = 65536
    def progress(status, remaining, total):
        if total * page_size > MAX_DATABASE or time.monotonic() > deadline:
            raise ValueError("The database backup exceeds its size or time limit.")
    with closing(connect(source, readonly=True)) as original, closing(connect(destination)) as copied:
        page_size = original.execute("PRAGMA page_size").fetchone()[0]
        original.backup(copied, pages=256, progress=progress, sleep=0.01)


def sanitize(path: Path, restored=False):
    with closing(connect(path)) as db:
        controller = quiescent(db)
        # DELETE alone leaves old credential bytes in free pages and WAL frames.
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA secure_delete=ON")
        with db:
            db.execute("DELETE FROM credentials")
            if restored:
                for value in records(db, "nodes"):
                    value.update(resources=None, last_seen=None, capabilities={}, state="unconfigured",
                                 error={"code": "restored_state", "message": "Refresh this machine after restore."})
                    value.pop("observed_at", None)
                    value.pop("boot_id", None)
                    db.execute("UPDATE nodes SET value=? WHERE id=?", (json.dumps(value), value["id"]))
        db.execute("VACUUM")
        schema(db)
        if db.execute("PRAGMA freelist_count").fetchone()[0] != 0 or db.execute("SELECT count(*) FROM credentials").fetchone()[0]:
            raise ValueError("The exported credential storage could not be cleared.")
    return controller
