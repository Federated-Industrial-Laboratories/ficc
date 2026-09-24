# SPDX-License-Identifier: Apache-2.0
"""Persist registered roots and deduplicated file operation receipts."""

import json
import time

from .errors import Failure


class FileStore:
    def __init__(self, store, table="file_operations"):
        if table not in {"file_operations", "transfers"}:
            raise ValueError("Invalid file state table.")
        self.store, self.table = store, table
        with store.lock, store.db:
            store.db.execute("CREATE TABLE IF NOT EXISTS file_roots (id TEXT PRIMARY KEY,value TEXT NOT NULL)")
            store.db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, actor TEXT NOT NULL, "
                             "key TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(actor,key))")

    def roots(self):
        with self.store.lock:
            return [json.loads(row[0]) for row in self.store.db.execute("SELECT value FROM file_roots ORDER BY rowid")]

    def root(self, root_id):
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM file_roots WHERE id=?", (root_id,)).fetchone()
        if row is None:
            raise Failure("root_missing", "The registered root was not found.", 404)
        return json.loads(row[0])

    def add_root(self, value):
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM file_roots").fetchone()[0] >= 64:
                raise Failure("capacity", "The root limit was reached.", 409)
            self.store.db.execute("INSERT INTO file_roots VALUES (?,?)", (value["id"], json.dumps(value)))

    def remove_root(self, root_id):
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM file_roots WHERE id=?", (root_id,))

    def all(self):
        return list(self.iterate())

    def iterate(self):
        before = 2**63 - 1
        while True:
            with self.store.lock:
                row = self.store.db.execute(f"SELECT rowid,value FROM {self.table} WHERE rowid < ? ORDER BY rowid DESC LIMIT 1", (before,)).fetchone()
            if row is None:
                return
            before = row[0]
            yield json.loads(row[1])

    def count(self):
        with self.store.lock:
            return self.store.db.execute(f"SELECT count(*) FROM {self.table}").fetchone()[0]

    def get(self, operation_id):
        with self.store.lock:
            row = self.store.db.execute(f"SELECT value FROM {self.table} WHERE id=?", (operation_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The file operation was not found.", 404)
        return json.loads(row[0])

    def existing(self, actor, key):
        with self.store.lock:
            row = self.store.db.execute(f"SELECT value FROM {self.table} WHERE actor=? AND key=?", (actor, key)).fetchone()
        return json.loads(row[0]) if row else None

    def insert(self, value):
        with self.store.lock, self.store.db:
            if self.store.db.execute(f"SELECT count(*) FROM {self.table}").fetchone()[0] >= 2048:
                raise Failure("capacity", "Retained file operation capacity is full.", 409)
            self.store.db.execute(f"INSERT INTO {self.table} VALUES (?,?,?,?)",
                                  (value["id"], value["actor"], value["key"], json.dumps(value)))

    def save(self, value):
        value["updated_at"] = time.time()
        with self.store.lock, self.store.db:
            self.store.db.execute(f"UPDATE {self.table} SET value=? WHERE id=?", (json.dumps(value), value["id"]))


def key_check(value):
    if not isinstance(value, str) or not 16 <= len(value) <= 128 or any(not 32 <= ord(char) <= 126 for char in value):
        raise Failure("invalid_key", "Use an Idempotency-Key with 16 to 128 printable ASCII characters.")
