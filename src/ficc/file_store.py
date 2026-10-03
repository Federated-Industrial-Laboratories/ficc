# SPDX-License-Identifier: Apache-2.0
"""Persist registered roots and deduplicated file operation receipts."""

import json
import time

from .errors import Failure
from .resource_store import Resources, decode, encode


class FileStore:
    def __init__(self, store, table="file_operations"):
        if table not in {"file_operations", "transfers"}:
            raise ValueError("Invalid file state table.")
        self.store, self.table = store, table

    def roots(self):
        with self.store.lock:
            return [json.loads(row[0]) for row in self.store.db.execute("SELECT value FROM file_roots ORDER BY rowid")]

    def root(self, root_id):
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM file_roots WHERE id=:p0", (root_id,)).fetchone()
        if row is None:
            raise Failure("root_missing", "The registered root was not found.", 404)
        return json.loads(row[0])

    def add_root(self, value):
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM file_roots").fetchone()[0] >= 64:
                raise Failure("capacity", "The root limit was reached.", 409)
            self.store.db.execute("INSERT INTO file_roots VALUES (:p0,:p1)", (value["id"], json.dumps(value)))

    def remove_root(self, root_id):
        with self.store.lock, self.store.db:
            Resources(self.store).remove("roots", root_id)
            self.store.db.execute("DELETE FROM file_roots WHERE id=:p0", (root_id,))

    def all(self):
        return list(self.iterate())

    def iterate(self, *, project_id=None):
        before = 2**63 - 1
        while True:
            with self.store.lock:
                condition = " AND project_id=:p1" if project_id is not None else ""
                row = self.store.db.execute(f"SELECT rowid,value,subject_id,project_id FROM {self.table} WHERE rowid < :p0"
                                            + condition + " ORDER BY rowid DESC LIMIT 1",
                                            (before, project_id) if project_id is not None else (before,)).fetchone()
            if row is None:
                return
            before = row[0]
            yield decode(row[1:])

    def count(self):
        with self.store.lock:
            return self.store.db.execute(f"SELECT count(*) FROM {self.table}").fetchone()[0]

    def get(self, operation_id):
        with self.store.lock:
            row = self.store.db.execute(f"SELECT value,subject_id,project_id FROM {self.table} WHERE id=:p0", (operation_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The file operation was not found.", 404)
        return decode(row)

    def existing(self, actor, key):
        with self.store.lock:
            row = self.store.db.execute(f"SELECT value,subject_id,project_id FROM {self.table} WHERE actor=:p0 AND key=:p1", (actor, key)).fetchone()
        return decode(row) if row else None

    def insert(self, value):
        with self.store.lock, self.store.db:
            if self.store.db.execute(f"SELECT count(*) FROM {self.table}").fetchone()[0] >= 2048:
                raise Failure("capacity", "Retained file operation capacity is full.", 409)
            self.store.db.execute(f"INSERT INTO {self.table} (id,actor,key,value,subject_id,project_id) VALUES (:p0,:p1,:p2,:p3,:p4,:p5)",
                                  (value["id"], value["actor"], value["key"], encode(value), value["subject_id"], value["project_id"]))

    def save(self, value):
        value["updated_at"] = time.time()
        with self.store.lock, self.store.db:
            self.store.db.execute(f"UPDATE {self.table} SET value=:p0 WHERE id=:p1", (encode(value), value["id"]))


def key_check(value):
    if not isinstance(value, str) or not 16 <= len(value) <= 128 or any(not 32 <= ord(char) <= 126 for char in value):
        raise Failure("invalid_key", "Use an Idempotency-Key with 16 to 128 printable ASCII characters.")
