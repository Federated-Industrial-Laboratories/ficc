# SPDX-License-Identifier: Apache-2.0
"""Save private workspaces with revision checks and bounded view records."""

import json
import secrets
import time

from .errors import Failure
from .identity_store import LOCAL_OWNER, LOCAL_PROJECT
from .workspace_schema import ViewUpdate, WorkspaceUpdate


def initialize(db) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS workspace_views ("
               "id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS workspace_surfaces (id TEXT PRIMARY KEY, value TEXT NOT NULL)")


class WorkspaceStore:
    def __init__(self, store, project_id=None, subject_id=None):
        self.store = store
        self.project_id = project_id
        self.subject_id = subject_id

    def scoped(self, principal):
        return WorkspaceStore(self.store, principal.project_id, principal.subject_id)

    def all(self) -> list[dict]:
        with self.store.lock:
            return [json.loads(row[0]) for row in self.store.db.execute(
                "SELECT value FROM workspaces WHERE (CAST(:p0 AS TEXT) IS NULL OR project_id=:p1) ORDER BY id",
                (self.project_id, self.project_id))]

    def get(self, identity: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM workspaces WHERE id=:p0 AND (CAST(:p1 AS TEXT) IS NULL OR project_id=:p2)",
                                        (identity, self.project_id, self.project_id)).fetchone()
        if row is None:
            raise Failure("not_found", "The workspace was not found.", 404)
        return json.loads(row[0])

    def create(self, name: str) -> dict:
        value = {"id": secrets.token_hex(16), "name": name, "revision": 0,
                 "instances": [], "updated_at": time.time()}
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM workspaces").fetchone()[0] >= 64:
                raise Failure("capacity", "The workspace limit was reached.", 409)
            self.store.db.execute("INSERT INTO workspaces VALUES (:p0,:p1,:p2)",
                                  (value["id"], json.dumps(value), self.project_id or LOCAL_PROJECT))
        return value

    def update(self, identity: str, body: WorkspaceUpdate) -> dict:
        with self.store.lock, self.store.db:
            current = self.get(identity)
            self.revision(current, body.revision)
            other_ids = {item["id"] for space in WorkspaceStore(self.store).all() if space["id"] != identity
                         for item in space["instances"]}
            if any(item.id in other_ids for item in body.instances):
                raise Failure("instance_conflict", "A panel identity belongs to another workspace.", 409)
            value = {"id": identity, **body.model_dump(), "revision": current["revision"] + 1,
                     "updated_at": time.time()}
            self.store.db.execute("UPDATE workspaces SET value=:p0 WHERE id=:p1", (json.dumps(value), identity))
            removed = {item["id"] for item in current["instances"]} - {item.id for item in body.instances}
            if removed:
                for key, raw in self.store.db.execute(
                        "SELECT id,value FROM workspace_views WHERE workspace_id=:p0", (identity,)).fetchall():
                    view = json.loads(raw)
                    if removed & set(view["layout"].get("panels", {})):
                        view.update(layout={}, revision=view["revision"] + 1)
                        self.store.db.execute("UPDATE workspace_views SET value=:p0 WHERE id=:p1", (json.dumps(view), key))
        return value

    def delete(self, identity: str, revision: int) -> None:
        with self.store.lock, self.store.db:
            self.revision(self.get(identity), revision)
            self.store.db.execute("DELETE FROM workspace_views WHERE workspace_id=:p0", (identity,))
            self.store.db.execute("DELETE FROM workspaces WHERE id=:p0", (identity,))
            for key, raw in self.store.db.execute("SELECT id,value FROM workspace_surfaces").fetchall():
                value = json.loads(raw)
                retained = [tile for tile in value["tiles"] if tile["workspace_id"] != identity]
                if len(retained) != len(value["tiles"]):
                    value.update(tiles=retained, layout={}, revision=value["revision"] + 1)
                    self.store.db.execute("UPDATE workspace_surfaces SET value=:p0 WHERE id=:p1", (json.dumps(value), key))

    @staticmethod
    def revision(current: dict, expected: int) -> None:
        if current["revision"] != expected:
            raise Failure("revision_conflict", "The saved value changed. Reload it before saving.", 409)

    def view(self, workspace: str, view_id: str) -> dict:
        with self.store.lock:
            self.get(workspace)
            row = self.store.db.execute("SELECT workspace_id,value,subject_id FROM workspace_views WHERE id=:p0",
                                        (view_id,)).fetchone()
            if row is None:
                # Older surfaces can reserve a view before its first saved layout.
                for raw, project, subject in self.store.db.execute("SELECT value,project_id,subject_id FROM workspace_surfaces"):
                    for tile in json.loads(raw)["tiles"]:
                        if tile["view_id"] != view_id:
                            continue
                        if ((self.subject_id is not None and subject != self.subject_id)
                                or (self.project_id is not None and project != self.project_id)):
                            raise Failure("not_found", "The workspace view was not found.", 404)
                        if tile["workspace_id"] != workspace:
                            raise Failure("view_conflict", "This view belongs to another workspace.", 409)
                return {"id": view_id, "workspace_id": workspace, "revision": 0, "layout": {}}
        if self.subject_id is not None and row[2] != self.subject_id:
            raise Failure("not_found", "The workspace view was not found.", 404)
        if row[0] != workspace:
            raise Failure("view_conflict", "This view belongs to another workspace.", 409)
        return json.loads(row[1])

    def save_view(self, workspace: str, view_id: str, body: ViewUpdate) -> dict:
        with self.store.lock, self.store.db:
            current = self.view(workspace, view_id)
            self.revision(current, body.revision)
            allowed = {item["id"] for item in self.get(workspace)["instances"]}
            if set(body.layout.get("panels", {})) - allowed:
                raise Failure("invalid_layout", "The layout refers to an unknown panel.")
            exists = self.store.db.execute("SELECT 1 FROM workspace_views WHERE id=:p0", (view_id,)).fetchone()
            if not exists and self.store.db.execute("SELECT count(*) FROM workspace_views").fetchone()[0] >= 256:
                raise Failure("capacity", "The saved view limit was reached. Remove an unused view.", 409)
            value = {**current, "revision": current["revision"] + 1, "layout": body.layout}
            self.store.db.execute("INSERT INTO workspace_views VALUES (:p0,:p1,:p2,:p3) "
                                  "ON CONFLICT(id) DO UPDATE SET value=excluded.value",
                                  (view_id, workspace, json.dumps(value), self.subject_id or LOCAL_OWNER))
        return value

    def surface(self, identity: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute("SELECT value,project_id,subject_id FROM workspace_surfaces WHERE id=:p0",
                                        (identity,)).fetchone()
        if row and ((self.project_id is not None and row[1] != self.project_id)
                    or (self.subject_id is not None and row[2] != self.subject_id)):
            raise Failure("not_found", "The workspace surface was not found.", 404)
        return json.loads(row[0]) if row else {"id": identity, "revision": 0, "tiles": [], "layout": {}}

    def layouts(self) -> dict:
        with self.store.lock:
            surfaces = [json.loads(row[0]) for row in self.store.db.execute(
                "SELECT value FROM workspace_surfaces WHERE (CAST(:p0 AS TEXT) IS NULL OR project_id=:p1) "
                "AND (CAST(:p2 AS TEXT) IS NULL OR subject_id=:p3) ORDER BY id",
                (self.project_id, self.project_id, self.subject_id, self.subject_id))]
            referenced = {tile["view_id"] for surface in surfaces for tile in surface["tiles"]}
            views = [json.loads(row[0]) for row in self.store.db.execute(
                "SELECT v.value FROM workspace_views v JOIN workspaces w ON w.id=v.workspace_id "
                "WHERE (CAST(:p0 AS TEXT) IS NULL OR w.project_id=:p1) AND (CAST(:p2 AS TEXT) IS NULL OR v.subject_id=:p3) ORDER BY v.id",
                (self.project_id, self.project_id, self.subject_id, self.subject_id))]
        return {"surfaces": [{key: surface[key] for key in ("id", "revision", "tiles")} for surface in surfaces],
                "unused_views": [{key: view[key] for key in ("id", "workspace_id", "revision")}
                                 for view in views if view["id"] not in referenced]}

    def delete_surface(self, identity: str, revision: int):
        with self.store.lock, self.store.db:
            self.revision(self.surface(identity), revision)
            self.store.db.execute("DELETE FROM workspace_surfaces WHERE id=:p0", (identity,))

    def delete_view(self, workspace: str, view_id: str, revision: int):
        with self.store.lock, self.store.db:
            self.revision(self.view(workspace, view_id), revision)
            if any(tile["view_id"] == view_id for surface in self.layouts()["surfaces"] for tile in surface["tiles"]):
                raise Failure("view_in_use", "Remove the saved window layout before removing this view.", 409)
            self.store.db.execute("DELETE FROM workspace_views WHERE id=:p0", (view_id,))

    def save_surface(self, identity: str, body) -> dict:
        with self.store.lock, self.store.db:
            current = self.surface(identity)
            self.revision(current, body.revision)
            for tile in body.tiles:
                view = self.view(tile.workspace_id, tile.view_id)
                project = self.store.db.execute("SELECT project_id FROM workspaces WHERE id=:p0", (tile.workspace_id,)).fetchone()
                if project[0] != (self.project_id or LOCAL_PROJECT):
                    raise Failure("not_found", "The workspace was not found.", 404)
                if self.store.db.execute("SELECT 1 FROM workspace_views WHERE id=:p0", (tile.view_id,)).fetchone() is None:
                    if self.store.db.execute("SELECT count(*) FROM workspace_views").fetchone()[0] >= 256:
                        raise Failure("capacity", "The saved view limit was reached. Remove an unused view.", 409)
                    self.store.db.execute("INSERT INTO workspace_views VALUES (:p0,:p1,:p2,:p3)",
                                          (tile.view_id, tile.workspace_id, json.dumps(view), self.subject_id or LOCAL_OWNER))
            if set(body.layout.get("panels", {})) - {tile.id for tile in body.tiles}:
                raise Failure("invalid_layout", "The surface refers to an unknown workspace tile.")
            exists = self.store.db.execute("SELECT 1 FROM workspace_surfaces WHERE id=:p0", (identity,)).fetchone()
            if not exists and self.store.db.execute("SELECT count(*) FROM workspace_surfaces").fetchone()[0] >= 64:
                raise Failure("capacity", "The saved surface limit was reached.", 409)
            value = {"id": identity, **body.model_dump(), "revision": current["revision"] + 1}
            self.store.db.execute("INSERT INTO workspace_surfaces VALUES (:p0,:p1,:p2,:p3) "
                                  "ON CONFLICT(id) DO UPDATE SET value=excluded.value",
                                  (identity, json.dumps(value), self.project_id or LOCAL_PROJECT, self.subject_id or LOCAL_OWNER))
        return value
