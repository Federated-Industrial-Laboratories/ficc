# SPDX-License-Identifier: Apache-2.0
"""Keep user identities and project membership separate from login credentials."""

import json
import secrets

from .errors import Failure
from .settings import SCOPES

LOCAL_OWNER = "00000000000000000000000000000001"
LOCAL_PROJECT = "00000000000000000000000000000002"
# These are implemented project boundaries, not a default permission policy.
PROJECT_SCOPES = frozenset({"workspaces:read", "workspaces:write", "modules:read",
                            "modules:execute", "audio:playback", "nodes:read", "resources:read",
                            "observations:read", "observations:resources",
                            "jobs:read", "jobs:execute", "jobs:cancel", "jobs:logs",
                            "files:read", "files:write", "files:delete", "files:mode",
                            "data:read", "data:export", "data:write", "data:manage",
                            "terminals:read", "terminals:execute", "terminals:stop",
                            "vm:read", "vm:power", "vm:console",
                            "container:read", "container:logs", "container:power",
                            "admin:read", "admin:logs", "admin:services", "admin:power",
                            "contributors:read", "contributors:manage"})


def initialize(db) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS identities (id TEXT PRIMARY KEY, label TEXT NOT NULL, "
               "disabled INTEGER NOT NULL, revision INTEGER NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, label TEXT NOT NULL, "
               "disabled INTEGER NOT NULL, revision INTEGER NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS project_memberships (project_id TEXT NOT NULL REFERENCES projects(id), "
               "subject_id TEXT NOT NULL REFERENCES identities(id), scopes TEXT NOT NULL, revision INTEGER NOT NULL, "
               "PRIMARY KEY(project_id,subject_id))")
    db.execute("INSERT OR IGNORE INTO identities VALUES (:p0,:p1,0,0)", (LOCAL_OWNER, "Local owner"))
    db.execute("INSERT OR IGNORE INTO projects VALUES (:p0,:p1,0,0)", (LOCAL_PROJECT, "Local project"))
    columns = {row[1] for row in db.execute("PRAGMA table_info(credentials)")}
    if "subject_id" not in columns:
        db.execute(f"ALTER TABLE credentials ADD COLUMN subject_id TEXT NOT NULL DEFAULT '{LOCAL_OWNER}'")
        db.execute(f"ALTER TABLE credentials ADD COLUMN project_id TEXT NOT NULL DEFAULT '{LOCAL_PROJECT}'")
    for table in ("workspaces", "workspace_surfaces"):
        if "project_id" not in {row[1] for row in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN project_id TEXT NOT NULL DEFAULT '{LOCAL_PROJECT}'")
    for table in ("workspace_views", "workspace_surfaces"):
        if "subject_id" not in {row[1] for row in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN subject_id TEXT NOT NULL DEFAULT '{LOCAL_OWNER}'")
    columns = {row[1] for row in db.execute("PRAGMA table_info(audit)")}
    if "subject_id" not in columns:
        db.execute("ALTER TABLE audit ADD COLUMN subject_id TEXT")
        db.execute("ALTER TABLE audit ADD COLUMN project_id TEXT")
        db.execute("UPDATE audit SET subject_id=:p0,project_id=:p1", (LOCAL_OWNER, LOCAL_PROJECT))


def public(row) -> dict:
    return {"id": row[0], "label": row[1], "disabled": bool(row[2]), "revision": row[3]}


class Identities:
    def __init__(self, store):
        self.store = store

    def _get(self, table: str, identity: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute(f"SELECT id,label,disabled,revision FROM {table} WHERE id=:p0",
                                        (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The identity or project was not found.", 404)
        return public(row)

    def user(self, identity: str) -> dict:
        return self._get("identities", identity)

    def project(self, identity: str) -> dict:
        return self._get("projects", identity)

    def users(self) -> list[dict]:
        with self.store.lock:
            return [public(row) for row in self.store.db.execute("SELECT id,label,disabled,revision FROM identities ORDER BY id")]

    def projects(self, subject: str) -> list[dict]:
        with self.store.lock:
            if subject == LOCAL_OWNER:
                rows = self.store.db.execute("SELECT id,label,disabled,revision FROM projects ORDER BY id")
            else:
                rows = self.store.db.execute("SELECT p.id,p.label,p.disabled,p.revision,m.scopes FROM projects p "
                                             "JOIN project_memberships m ON m.project_id=p.id "
                                             "WHERE m.subject_id=:p0 AND p.disabled=0 ORDER BY p.id", (subject,))
            return [public(row) for row in rows if subject == LOCAL_OWNER or json.loads(row[4])]

    def create(self, kind: str, label: str) -> dict:
        if kind not in {"user", "project"} or not isinstance(label, str) or not label.strip() or len(label) > 80:
            raise Failure("invalid_identity", "Select an identity type and a label of 1 to 80 characters.")
        table = "identities" if kind == "user" else "projects"
        identity = secrets.token_hex(16)
        with self.store.lock, self.store.db:
            if self.store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] >= 256:
                raise Failure("capacity", "The identity or project limit was reached.", 409)
            self.store.db.execute(f"INSERT INTO {table} VALUES (:p0,:p1,0,0)", (identity, label.strip()))
        return self._get(table, identity)

    def update(self, kind: str, identity: str, label: str, disabled: bool, revision: int) -> dict:
        if kind not in {"user", "project"} or not isinstance(label, str) or not label.strip() or len(label) > 80:
            raise Failure("invalid_identity", "Select an identity type and a label of 1 to 80 characters.")
        if identity in {LOCAL_OWNER, LOCAL_PROJECT} and disabled:
            raise Failure("recovery_required", "Keep the local recovery identity and project enabled.", 409)
        table = "identities" if kind == "user" else "projects"
        with self.store.lock, self.store.db:
            if self._get(table, identity)["revision"] != revision:
                raise Failure("revision_conflict", "The saved value changed. Reload it before saving.", 409)
            self.store.db.execute(f"UPDATE {table} SET label=:p0,disabled=:p1,revision=revision+1 WHERE id=:p2",
                                  (label.strip(), int(disabled), identity))
            if disabled:
                column = "subject_id" if kind == "user" else "project_id"
                self.store.db.execute(f"DELETE FROM credentials WHERE {column}=:p0", (identity,))
        return self._get(table, identity)

    def members(self, project: str) -> list[dict]:
        with self.store.lock:
            self.project(project)
            return [{"subject_id": row[0], "scopes": json.loads(row[1]), "revision": row[2]}
                    for row in self.store.db.execute("SELECT subject_id,scopes,revision FROM project_memberships "
                                                     "WHERE project_id=:p0 ORDER BY subject_id", (project,))]

    def membership(self, project: str, subject: str, scopes: list[str], revision: int) -> dict:
        if subject == LOCAL_OWNER:
            raise Failure("recovery_required", "The local recovery identity has fixed owner access.", 409)
        if not isinstance(scopes, list) or any(not isinstance(s, str) for s in scopes) or set(scopes) - PROJECT_SCOPES:
            raise Failure("invalid_scope", "Select supported project permission scopes.")
        with self.store.lock, self.store.db:
            self.project(project)
            self.user(subject)
            row = self.store.db.execute("SELECT revision FROM project_memberships WHERE project_id=:p0 AND subject_id=:p1",
                                        (project, subject)).fetchone()
            if (row[0] if row else 0) != revision:
                raise Failure("revision_conflict", "The membership changed. Reload it before saving.", 409)
            if not row and self.store.db.execute("SELECT count(*) FROM project_memberships").fetchone()[0] >= 4096:
                raise Failure("capacity", "The membership limit was reached.", 409)
            self.store.db.execute("INSERT INTO project_memberships VALUES (:p0,:p1,:p2,:p3) "
                                  "ON CONFLICT(project_id,subject_id) DO UPDATE SET scopes=excluded.scopes,revision=excluded.revision",
                                  (project, subject, json.dumps(sorted(set(scopes))), revision + 1))
            # Revocation cannot be undone by removing and later restoring membership.
            if not scopes:
                self.store.db.execute("DELETE FROM credentials WHERE project_id=:p0 AND subject_id=:p1", (project, subject))
        return {"subject_id": subject, "scopes": sorted(set(scopes)), "revision": revision + 1}

    def access(self, subject: str, project: str) -> set[str]:
        with self.store.lock:
            user = self.user(subject)
            space = self.project(project)
            if user["disabled"] or space["disabled"]:
                raise Failure("unauthenticated", "The identity or project is disabled.", 401)
            if subject == LOCAL_OWNER:
                return set(SCOPES)
            row = self.store.db.execute("SELECT scopes FROM project_memberships WHERE project_id=:p0 AND subject_id=:p1",
                                        (project, subject)).fetchone()
            if row is None or not json.loads(row[0]):
                raise Failure("unauthenticated", "Project membership is required.", 401)
            return set(json.loads(row[0])) & PROJECT_SCOPES
