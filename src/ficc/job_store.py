# SPDX-License-Identifier: Apache-2.0
"""Persist frozen operations and their idempotency identities."""

import json
import time

from ficc_node.job_spec import TERMINAL

from .errors import Failure
from .store import Store


class JobStore:
    def __init__(self, store: Store):
        self.store = store
        with store.lock, store.db:
            store.db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, "
                             "actor TEXT NOT NULL, key TEXT NOT NULL, digest TEXT NOT NULL, "
                             "value TEXT NOT NULL, UNIQUE(actor,key))")

    def all(self, limit: int = 2048) -> list[dict]:
        with self.store.lock:
            rows = self.store.db.execute("SELECT value FROM operations ORDER BY rowid DESC LIMIT ?", (limit,))
            return [json.loads(row[0]) for row in rows]

    def get(self, operation_id: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM operations WHERE id=?", (operation_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The operation was not found.", 404)
        return json.loads(row[0])

    def existing(self, actor: str, key: str) -> dict | None:
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM operations WHERE actor=? AND key=?", (actor, key)).fetchone()
        return json.loads(row[0]) if row else None

    def active(self, node_id: str) -> bool:
        return any(target["node_id"] == node_id and target["state"] not in TERMINAL
                   for operation in self.all() for target in operation["targets"])

    def insert(self, operation: dict) -> None:
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM operations").fetchone()[0] >= 2048:
                raise Failure("capacity", "Retained operation capacity is full.", 409)
            self.store.db.execute("INSERT INTO operations VALUES (?,?,?,?,?)",
                                  (operation["id"], operation["actor"], operation["key"], operation["digest"], json.dumps(operation)))

    def save(self, operation: dict) -> None:
        operation["updated_at"] = time.time()
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE operations SET value=? WHERE id=?", (json.dumps(operation), operation["id"]))
