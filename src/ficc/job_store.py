# SPDX-License-Identifier: Apache-2.0
"""Persist frozen operations and their idempotency identities."""

import time

from ficc_node.job_spec import TERMINAL

from .errors import Failure
from .resource_store import decode, encode
from .store import Store


class JobStore:
    def __init__(self, store: Store):
        self.store = store

    def all(self, limit: int = 2048, *, project_id: str | None = None) -> list[dict]:
        with self.store.lock:
            query = "SELECT value,subject_id,project_id FROM operations"
            if project_id is not None:
                query += " WHERE project_id=:p1"
            rows = self.store.db.execute(query + " ORDER BY rowid DESC LIMIT :p0",
                                         (limit, project_id) if project_id is not None else (limit,))
            return [decode(row) for row in rows]

    def get(self, operation_id: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute("SELECT value,subject_id,project_id FROM operations WHERE id=:p0", (operation_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The operation was not found.", 404)
        return decode(row)

    def existing(self, actor: str, key: str) -> dict | None:
        with self.store.lock:
            row = self.store.db.execute("SELECT value,subject_id,project_id FROM operations WHERE actor=:p0 AND key=:p1", (actor, key)).fetchone()
        return decode(row) if row else None

    def active(self, node_id: str) -> bool:
        return any(target["node_id"] == node_id and target["state"] not in TERMINAL
                   for operation in self.all() for target in operation["targets"])

    def insert(self, operation: dict) -> None:
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM operations").fetchone()[0] >= 2048:
                raise Failure("capacity", "Retained operation capacity is full.", 409)
            self.store.db.execute("INSERT INTO operations (id,actor,key,digest,value,subject_id,project_id) "
                                  "VALUES (:p0,:p1,:p2,:p3,:p4,:p5,:p6)",
                                  (operation["id"], operation["actor"], operation["key"], operation["digest"], encode(operation),
                                   operation["subject_id"], operation["project_id"]))

    def save(self, operation: dict) -> None:
        operation["updated_at"] = time.time()
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE operations SET value=:p0 WHERE id=:p1", (encode(operation), operation["id"]))
