# SPDX-License-Identifier: Apache-2.0
"""Save private workspaces with revision checks and bounded view records."""

import json
import secrets
import time

from .errors import Failure
from .workspace_schema import ViewUpdate, WorkspaceUpdate


def initialize(db) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS workspace_views ("
               "id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS workspace_surfaces (id TEXT PRIMARY KEY, value TEXT NOT NULL)")


class WorkspaceStore:
    def __init__(self, store):
        self.store = store

    def all(self) -> list[dict]:
        with self.store.lock:
            return [json.loads(row[0]) for row in self.store.db.execute(
                "SELECT value FROM workspaces ORDER BY id")]

    def get(self, identity: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM workspaces WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The workspace was not found.", 404)
        return json.loads(row[0])

    def create(self, name: str) -> dict:
        value = {"id": secrets.token_hex(16), "name": name, "revision": 0,
                 "instances": [], "updated_at": time.time()}
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM workspaces").fetchone()[0] >= 64:
                raise Failure("capacity", "The workspace limit was reached.", 409)
            self.store.db.execute("INSERT INTO workspaces VALUES (?,?)", (value["id"], json.dumps(value)))
        return value

    def update(self, identity: str, body: WorkspaceUpdate) -> dict:
        with self.store.lock, self.store.db:
            current = self.get(identity)
            self.revision(current, body.revision)
            other_ids = {item["id"] for space in self.all() if space["id"] != identity
                         for item in space["instances"]}
            if any(item.id in other_ids for item in body.instances):
                raise Failure("instance_conflict", "A panel identity belongs to another workspace.", 409)
            value = {"id": identity, **body.model_dump(), "revision": current["revision"] + 1,
                     "updated_at": time.time()}
            self.store.db.execute("UPDATE workspaces SET value=? WHERE id=?", (json.dumps(value), identity))
            removed = {item["id"] for item in current["instances"]} - {item.id for item in body.instances}
            if removed:
                for key, raw in self.store.db.execute(
                        "SELECT id,value FROM workspace_views WHERE workspace_id=?", (identity,)).fetchall():
                    view = json.loads(raw)
                    if removed & set(view["layout"].get("panels", {})):
                        view.update(layout={}, revision=view["revision"] + 1)
                        self.store.db.execute("UPDATE workspace_views SET value=? WHERE id=?", (json.dumps(view), key))
        return value

    def delete(self, identity: str, revision: int) -> None:
        with self.store.lock, self.store.db:
            self.revision(self.get(identity), revision)
            self.store.db.execute("DELETE FROM workspace_views WHERE workspace_id=?", (identity,))
            self.store.db.execute("DELETE FROM workspaces WHERE id=?", (identity,))
            for key, raw in self.store.db.execute("SELECT id,value FROM workspace_surfaces").fetchall():
                value = json.loads(raw)
                retained = [tile for tile in value["tiles"] if tile["workspace_id"] != identity]
                if len(retained) != len(value["tiles"]):
                    value.update(tiles=retained, layout={}, revision=value["revision"] + 1)
                    self.store.db.execute("UPDATE workspace_surfaces SET value=? WHERE id=?", (json.dumps(value), key))

    @staticmethod
    def revision(current: dict, expected: int) -> None:
        if current["revision"] != expected:
            raise Failure("revision_conflict", "The saved value changed. Reload it before saving.", 409)

    def view(self, workspace: str, view_id: str) -> dict:
        with self.store.lock:
            self.get(workspace)
            row = self.store.db.execute("SELECT workspace_id,value FROM workspace_views WHERE id=?",
                                        (view_id,)).fetchone()
        if row is None:
            return {"id": view_id, "workspace_id": workspace, "revision": 0, "layout": {}}
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
            exists = self.store.db.execute("SELECT 1 FROM workspace_views WHERE id=?", (view_id,)).fetchone()
            if not exists and self.store.db.execute("SELECT count(*) FROM workspace_views").fetchone()[0] >= 256:
                raise Failure("capacity", "The saved view limit was reached. Remove an unused view.", 409)
            value = {**current, "revision": current["revision"] + 1, "layout": body.layout}
            self.store.db.execute("INSERT OR REPLACE INTO workspace_views VALUES (?,?,?)",
                                  (view_id, workspace, json.dumps(value)))
        return value

    def surface(self, identity: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM workspace_surfaces WHERE id=?", (identity,)).fetchone()
        return json.loads(row[0]) if row else {"id": identity, "revision": 0, "tiles": [], "layout": {}}

    def layouts(self) -> dict:
        with self.store.lock:
            surfaces = [json.loads(row[0]) for row in self.store.db.execute("SELECT value FROM workspace_surfaces ORDER BY id")]
            referenced = {tile["view_id"] for surface in surfaces for tile in surface["tiles"]}
            views = [json.loads(row[0]) for row in self.store.db.execute("SELECT value FROM workspace_views ORDER BY id")]
        return {"surfaces": [{key: surface[key] for key in ("id", "revision", "tiles")} for surface in surfaces],
                "unused_views": [{key: view[key] for key in ("id", "workspace_id", "revision")}
                                 for view in views if view["id"] not in referenced]}

    def delete_surface(self, identity: str, revision: int):
        with self.store.lock, self.store.db:
            self.revision(self.surface(identity), revision)
            self.store.db.execute("DELETE FROM workspace_surfaces WHERE id=?", (identity,))

    def delete_view(self, workspace: str, view_id: str, revision: int):
        with self.store.lock, self.store.db:
            self.revision(self.view(workspace, view_id), revision)
            if any(tile["view_id"] == view_id for surface in self.layouts()["surfaces"] for tile in surface["tiles"]):
                raise Failure("view_in_use", "Remove the saved window layout before removing this view.", 409)
            self.store.db.execute("DELETE FROM workspace_views WHERE id=?", (view_id,))

    def save_surface(self, identity: str, body) -> dict:
        with self.store.lock, self.store.db:
            current = self.surface(identity)
            self.revision(current, body.revision)
            for tile in body.tiles:
                self.view(tile.workspace_id, tile.view_id)
            if set(body.layout.get("panels", {})) - {tile.id for tile in body.tiles}:
                raise Failure("invalid_layout", "The surface refers to an unknown workspace tile.")
            exists = self.store.db.execute("SELECT 1 FROM workspace_surfaces WHERE id=?", (identity,)).fetchone()
            if not exists and self.store.db.execute("SELECT count(*) FROM workspace_surfaces").fetchone()[0] >= 64:
                raise Failure("capacity", "The saved surface limit was reached.", 409)
            value = {"id": identity, **body.model_dump(), "revision": current["revision"] + 1}
            self.store.db.execute("INSERT OR REPLACE INTO workspace_surfaces VALUES (?,?)", (identity, json.dumps(value)))
        return value
