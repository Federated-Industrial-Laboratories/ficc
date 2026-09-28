# SPDX-License-Identifier: Apache-2.0
"""Keep bounded editor intents without storing file text in workspace state."""

import json
import time

from .errors import Failure
from .module_editor_validation import MAX_RECORD, validate_records  # noqa: F401

MAX_OPERATIONS = 128


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS module_editor_operations ("
               "id TEXT PRIMARY KEY, actor TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(actor,key))")


def encoded(value):
    raw = json.dumps(value, allow_nan=False)
    if len(raw.encode()) > MAX_RECORD:
        raise Failure("editor_capacity", "The edit receipt exceeds its byte limit.", 409)
    return raw


class EditorStore:
    def __init__(self, store):
        self.store = store
        with store.lock, store.db:
            initialize(store.db)

    def get(self, identity):
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_editor_operations WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise Failure("editor_missing", "The edit receipt was not found.", 404)
        return json.loads(row[0])

    def all(self):
        with self.store.lock:
            return [json.loads(row[0]) for row in self.store.db.execute(
                "SELECT value FROM module_editor_operations ORDER BY rowid DESC")]

    def insert(self, value):
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM module_editor_operations").fetchone()[0] >= MAX_OPERATIONS:
                raise Failure("editor_capacity", "Remove completed edit receipts before saving more files.", 409)
            self.store.db.execute("INSERT INTO module_editor_operations VALUES (?,?,?,?)",
                                  (value["id"], value["actor"], value["key"], encoded(value)))

    def save(self, value):
        value["updated_at"] = time.time()
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE module_editor_operations SET value=? WHERE id=?", (encoded(value), value["id"]))

    def remove(self, identity):
        value = self.get(identity)
        if any(item["state"] in {"pending", "unknown"} or item.get("retained") for item in value["items"]):
            raise Failure("editor_retained", "Recover and remove all retained copies first.", 409)
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM module_editor_operations WHERE id=?", (identity,))


def retained(store, *, root_id=None, node_id=None, workspace_id=None, instance_id=None, digest=None):
    for value in EditorStore(store).all():
        if workspace_id is not None and value["workspace_id"] != workspace_id:
            continue
        if instance_id is not None and value["instance_id"] != instance_id:
            continue
        if digest is not None and value["package_digest"] != digest:
            continue
        for item in value["items"]:
            if root_id is not None and item["root_id"] != root_id:
                continue
            if node_id is not None and item["root"].get("node_id") != node_id:
                continue
            if item["retained"] or item["state"] in {"pending", "unknown"}:
                return True
    return False
