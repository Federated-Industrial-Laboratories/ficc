# SPDX-License-Identifier: Apache-2.0
"""Store bounded inventory, grants, and audit records on local disk."""

import json
import os
import sqlite3
import stat
import threading
import time
from pathlib import Path
from typing import Any

from .errors import Failure
from .settings import MAX_NODES, private_directory


class Store:
    def __init__(self, path: Path):
        private_directory(path.parent)
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("State file must be owned by the current account.")
            if info.st_mode & 0o077:
                raise ValueError("State file must have mode 0600.")
        else:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3):
            self.db.close()
            raise ValueError("The state schema is not supported.")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY, digest TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
                label TEXT NOT NULL, scopes TEXT NOT NULL, nodes TEXT,
                expires REAL NOT NULL, csrf TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
                action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT 'local-owner');
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            PRAGMA user_version=3;
        """)
        if "actor" not in {row[1] for row in self.db.execute("PRAGMA table_info(audit)")}:
            self.db.execute("ALTER TABLE audit ADD COLUMN actor TEXT NOT NULL DEFAULT 'local-owner'")
        if "roots" not in {row[1] for row in self.db.execute("PRAGMA table_info(credentials)")}:
            self.db.execute("ALTER TABLE credentials ADD COLUMN roots TEXT NOT NULL DEFAULT 'null'")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def get_setting(self, key: str, default: Any) -> Any:
        with self.lock:
            row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, json.dumps(value)))

    def nodes(self) -> list[dict]:
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("SELECT value FROM nodes ORDER BY id")]

    def node(self, node_id: str) -> dict:
        with self.lock:
            row = self.db.execute("SELECT value FROM nodes WHERE id=?", (node_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The machine was not found.", 404)
        return json.loads(row[0])

    def save_node(self, node: dict) -> None:
        with self.lock, self.db:
            if self.db.execute("SELECT 1 FROM nodes WHERE id=?", (node["id"],)).fetchone() is None:
                if self.db.execute("SELECT count(*) FROM nodes").fetchone()[0] >= MAX_NODES:
                    raise Failure("capacity", "The machine limit was reached.", 409)
            self.db.execute("INSERT OR REPLACE INTO nodes VALUES (?,?)", (node["id"], json.dumps(node)))

    def delete_node(self, node_id: str) -> None:
        with self.lock, self.db:
            self.db.execute("DELETE FROM nodes WHERE id=?", (node_id,))

    def audit(self, action: str, target: str, outcome: str = "success", actor: str = "local-owner") -> None:
        with self.lock, self.db:
            self.db.execute("INSERT INTO audit(at,action,target,outcome,actor) VALUES (?,?,?,?,?)",
                            (time.time(), action, target, outcome, actor))
            self.db.execute("DELETE FROM audit WHERE id <= (SELECT max(id)-10000 FROM audit)")

    def events(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                "SELECT id,at,action,target,outcome,actor FROM audit ORDER BY id DESC LIMIT 200").fetchall()
        return [dict(zip(("id", "at", "action", "target", "outcome", "actor"), r, strict=True)) for r in rows]
