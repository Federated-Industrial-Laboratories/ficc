# SPDX-License-Identifier: Apache-2.0
"""Store project resource assignments and durable operation ownership."""

import json

from .errors import Failure
from .identity_store import LOCAL_OWNER, LOCAL_PROJECT
from .settings import MAX_NODES

OWNED_TABLES = frozenset({"operations", "file_operations", "transfers", "terminals"})


def initialize(db) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS project_resources (project_id TEXT PRIMARY KEY REFERENCES projects(id), "
               "nodes TEXT NOT NULL, roots TEXT NOT NULL, revision INTEGER NOT NULL)")
    for table in sorted(OWNED_TABLES):
        columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
        if "subject_id" not in columns:
            db.execute(f"ALTER TABLE {table} ADD COLUMN subject_id TEXT NOT NULL DEFAULT '{LOCAL_OWNER}'")
            db.execute(f"ALTER TABLE {table} ADD COLUMN project_id TEXT NOT NULL DEFAULT '{LOCAL_PROJECT}'")


def encode(value: dict) -> str:
    return json.dumps({key: item for key, item in value.items() if key not in {"subject_id", "project_id"}})


def decode(row) -> dict:
    return {**json.loads(row[0]), "subject_id": row[1], "project_id": row[2]}


class Resources:
    def __init__(self, store):
        self.store = store

    def module_instance(self, principal, workspace: str, identity: str, *, digest=None) -> dict:
        """Join a private panel binding; callers apply current policy before returning data."""
        principal.require_host("workspaces:read")
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM workspaces WHERE id=:p0 AND project_id=:p1",
                                        (workspace, principal.project_id)).fetchone()
        if row is None:
            raise Failure("not_found", "The workspace was not found.", 404)
        item = next((item for item in json.loads(row[0])["instances"] if item["id"] == identity), None)
        if item is None:
            if digest is not None:
                raise Failure("instance_changed", "The module panel was removed.", 409)
            raise Failure("not_found", "The module panel was not found.", 404)
        if digest is not None and item["digest"] != digest:
            raise Failure("instance_changed", "The module package changed.", 409)
        return item

    def module_operation(self, principal, workspace: str, identity: str, value: dict) -> dict:
        """Bind a retained receipt to its current project panel and assigned systems."""
        instance = self.module_instance(principal, workspace, identity, digest=value["package_digest"])
        if (value["instance_id"] != identity
                or any(item["node_id"] not in instance["targets"] for item in value["targets"])):
            raise Failure("instance_changed", "The operation no longer belongs to this panel.", 409)
        for item in value["targets"]:
            principal.require_host("nodes:read", item["node_id"])
        return instance

    def get(self, project: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute("SELECT nodes,roots,revision FROM project_resources WHERE project_id=:p0",
                                        (project,)).fetchone()
        return {"node_ids": json.loads(row[0]) if row else [], "root_ids": json.loads(row[1]) if row else [],
                "revision": row[2] if row else 0}

    def save(self, project: str, nodes: list[str], roots: list[str], revision: int) -> dict:
        if (not isinstance(nodes, list) or not isinstance(roots, list) or len(nodes) > 2 * MAX_NODES or len(roots) > 64
                or any(not isinstance(item, str) for item in nodes + roots)
                or len(set(nodes)) != len(nodes) or len(set(roots)) != len(roots)
                or type(revision) is not int or not 0 <= revision < 2**53 - 1):
            raise Failure("invalid_resources", "Select distinct registered machines and folders.")
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT id FROM projects WHERE id=:p0", (project,)).fetchone() is None:
                raise Failure("not_found", "The project was not found.", 404)
            if self.get(project)["revision"] != revision:
                raise Failure("revision_conflict", "Project resources changed. Reload them before saving.", 409)
            for node in nodes:
                self.store.endpoint_kind(node)
            for root in roots:
                row = self.store.db.execute("SELECT value FROM file_roots WHERE id=:p0", (root,)).fetchone()
                if row is None:
                    raise Failure("invalid_resources", "The registered folder was not found.")
                node = json.loads(row[0]).get("node_id")
                if node is not None and node not in nodes:
                    raise Failure("invalid_resources", "Assign the folder's machine to this project too.")
            self.store.db.execute("INSERT INTO project_resources VALUES (:p0,:p1,:p2,:p3) "
                                  "ON CONFLICT(project_id) DO UPDATE SET nodes=excluded.nodes,roots=excluded.roots,revision=excluded.revision",
                                  (project, json.dumps(sorted(nodes)), json.dumps(sorted(roots)), revision + 1))
        return self.get(project)

    def remove(self, kind: str, identity: str) -> None:
        if kind not in {"nodes", "roots"}:
            raise ValueError("The resource type is invalid.")
        with self.store.lock, self.store.db:
            rows = self.store.db.execute(f"SELECT project_id,{kind} FROM project_resources").fetchall()
            for project, raw in rows:
                values = json.loads(raw)
                if identity in values:
                    self.store.db.execute(f"UPDATE project_resources SET {kind}=:p0,revision=revision+1 WHERE project_id=:p1",
                                          (json.dumps([item for item in values if item != identity]), project))
