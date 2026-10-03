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
        self.lock = threading.RLock()
        from .state_provider import AtomicConnection, configuration, open_provider
        if configuration(path.parent) is not None and (path.exists() or path.is_symlink()):
            raise ValueError("A local database remains beside the configured provider. Resume the state migration before starting.")
        provider = open_provider(path.parent)
        if provider is not None:
            self.db = provider
            return
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("State file must be owned by the current account.")
            if info.st_mode & 0o077:
                raise ValueError("State file must have mode 0600.")
        else:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(path, check_same_thread=False, factory=AtomicConnection)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15):
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
            CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, actor TEXT NOT NULL,
                key TEXT NOT NULL, digest TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(actor,key));
            CREATE TABLE IF NOT EXISTS file_roots (id TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS file_operations (id TEXT PRIMARY KEY, actor TEXT NOT NULL,
                key TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(actor,key));
            CREATE TABLE IF NOT EXISTS transfers (id TEXT PRIMARY KEY, actor TEXT NOT NULL,
                key TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(actor,key));
            CREATE TABLE IF NOT EXISTS terminals (id TEXT PRIMARY KEY, actor TEXT NOT NULL,
                key TEXT NOT NULL, digest TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(actor,key));
        """)
        if "actor" not in {row[1] for row in self.db.execute("PRAGMA table_info(audit)")}:
            self.db.execute("ALTER TABLE audit ADD COLUMN actor TEXT NOT NULL DEFAULT 'local-owner'")
        if "roots" not in {row[1] for row in self.db.execute("PRAGMA table_info(credentials)")}:
            self.db.execute("ALTER TABLE credentials ADD COLUMN roots TEXT NOT NULL DEFAULT 'null'")
        from .agent_store import initialize
        initialize(self.db)
        from .module_editor_store import initialize as initialize_editor
        from .modules import initialize as initialize_modules
        from .workspace_store import initialize as initialize_workspaces
        initialize_editor(self.db)
        from .module_vm_store import initialize as initialize_vms
        initialize_vms(self.db)
        from .module_proxmox_store import initialize as initialize_proxmox
        initialize_proxmox(self.db)
        from .module_containers_store import initialize as initialize_containers
        initialize_containers(self.db)
        from .module_admin_store import initialize as initialize_administration
        initialize_administration(self.db)
        from .module_adapter_store import initialize as initialize_adapters
        from .module_windows_store import initialize as initialize_windows
        initialize_adapters(self.db)
        initialize_windows(self.db)
        initialize_modules(self.db)
        initialize_workspaces(self.db)
        self.db.commit()
        from .identity_store import initialize as initialize_identities
        try:
            self.db.execute("BEGIN IMMEDIATE")
            initialize_identities(self.db)
            from .resource_store import initialize as initialize_resources
            initialize_resources(self.db)
            from .policy_store import initialize as initialize_policies
            initialize_policies(self.db)
            from .external_identity_store import initialize as initialize_external_identities
            initialize_external_identities(self.db)
            from .contributor_store import initialize as initialize_contributors
            initialize_contributors(self.db)
            from .workloads.records import initialize as initialize_workloads
            initialize_workloads(self.db)
            from .dataset_store import initialize as initialize_datasets
            initialize_datasets(self.db)
            from .source_store import initialize as initialize_sources
            initialize_sources(self.db)
            from .inspection_store import backfill as backfill_inspections
            from .inspection_store import initialize as initialize_inspections
            initialize_inspections(self.db)
            if version < 15:
                backfill_inspections(self.db)
            self.db.execute("PRAGMA user_version=15")
            self.db.commit()
        except BaseException:
            self.db.rollback()
            self.db.close()
            raise

    def table_names(self) -> set[str]:
        if hasattr(self.db, "table_names"):
            return self.db.table_names()
        return {row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def begin(self) -> None:
        if hasattr(self.db, "begin"):
            self.db.begin()
        else:
            self.db.execute("BEGIN IMMEDIATE")

    def close(self) -> None:
        self.db.close()

    def get_setting(self, key: str, default: Any) -> Any:
        with self.lock:
            row = self.db.execute("SELECT value FROM settings WHERE key=:p0", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT INTO settings VALUES (:p0,:p1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))

    def nodes(self) -> list[dict]:
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("SELECT value FROM nodes ORDER BY id")]

    def node(self, node_id: str) -> dict:
        with self.lock:
            row = self.db.execute("SELECT value FROM nodes WHERE id=:p0", (node_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The machine was not found.", 404)
        return json.loads(row[0])

    def save_node(self, node: dict) -> None:
        with self.lock, self.db:
            if self.db.execute("SELECT 1 FROM nodes WHERE id=:p0", (node["id"],)).fetchone() is None:
                if self.db.execute("SELECT count(*) FROM nodes").fetchone()[0] >= MAX_NODES:
                    raise Failure("capacity", "The machine limit was reached.", 409)
            self.db.execute("INSERT INTO nodes VALUES (:p0,:p1) ON CONFLICT(id) DO UPDATE SET value=excluded.value", (node["id"], json.dumps(node)))

    def endpoint_kind(self, endpoint_id: str) -> str:
        with self.lock:
            linux = self.db.execute("SELECT 1 FROM nodes WHERE id=:p0", (endpoint_id,)).fetchone()
            windows = self.db.execute("SELECT 1 FROM module_windows_endpoints WHERE id=:p0", (endpoint_id,)).fetchone()
        if linux and windows:
            raise Failure("endpoint_conflict", "Multiple endpoint types use this identity.", 409)
        if not linux and not windows:
            raise Failure("not_found", "The registered endpoint was not found.", 404)
        return "linux-ssh" if linux else "windows"

    def delete_node(self, node_id: str) -> None:
        with self.lock, self.db:
            from .resource_store import Resources
            Resources(self).remove("nodes", node_id)
            self.db.execute("DELETE FROM nodes WHERE id=:p0", (node_id,))

    def audit(self, action: str, target: str, outcome: str = "success", actor: str = "local-owner",
              subject_id: str | None = None, project_id: str | None = None) -> None:
        with self.lock, self.db:
            if subject_id is None:
                from .identity_store import LOCAL_OWNER, LOCAL_PROJECT
                row = self.db.execute("SELECT subject_id,project_id FROM credentials WHERE id=:p0", (actor,)).fetchone()
                if row:
                    subject_id, project_id = row
                elif actor == "local-owner":
                    subject_id, project_id = LOCAL_OWNER, LOCAL_PROJECT
            self.db.execute("INSERT INTO audit(at,action,target,outcome,actor,subject_id,project_id) VALUES (:p0,:p1,:p2,:p3,:p4,:p5,:p6)",
                            (time.time(), action, target, outcome, actor, subject_id, project_id))
            self.db.execute("DELETE FROM audit WHERE id <= (SELECT max(id)-10000 FROM audit)")

    def events(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                "SELECT id,at,action,target,outcome,actor,subject_id,project_id FROM audit ORDER BY id DESC LIMIT 200").fetchall()
        return [dict(zip(("id", "at", "action", "target", "outcome", "actor", "subject_id", "project_id"), r, strict=True)) for r in rows]
