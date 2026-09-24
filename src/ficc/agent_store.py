# SPDX-License-Identifier: Apache-2.0
"""Keep bounded agent and bus records in the controller database."""

import hashlib
import json
import secrets
import time

from .errors import Failure

CAPS = {"agent_profiles": 128, "agents": 512, "bus_runs": 128,
        "bus_messages": 16384, "bus_deliveries": 32768}
CLOSED = {"stopped", "exited"}
SETTLED = {"session-included", "tool-read", "failed", "cancelled"}


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False,
                                     separators=(",", ":")).encode()).hexdigest()


def initialize(db):
    for table in CAPS:
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY,actor TEXT,key TEXT,"
                   "digest TEXT,value TEXT,UNIQUE(actor,key))")


class AgentStore:
    def __init__(self, store):
        self.store = store

    def all(self, table):
        assert table in CAPS
        with self.store.lock:
            return [json.loads(row[0]) for row in self.store.db.execute(f"SELECT value FROM {table} ORDER BY rowid")]

    def get(self, table, identity):
        assert table in CAPS
        with self.store.lock:
            row = self.store.db.execute(f"SELECT value FROM {table} WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The agent or bus record was not found.", 404)
        return json.loads(row[0])

    def retry(self, table, actor, key, intent):
        assert table in CAPS
        with self.store.lock:
            row = self.store.db.execute(f"SELECT digest,value FROM {table} WHERE actor=? AND key=?", (actor, key)).fetchone()
        if row is None:
            return None
        if row[0] != fingerprint(intent):
            raise Failure("idempotency_conflict", "The request key already identifies different content.", 409)
        return json.loads(row[1])

    def new(self, table, actor, key, intent, **fields):
        return {"id": secrets.token_hex(16), "actor": actor, "key": key,
                "digest": fingerprint(intent), "created_at": time.time(), **fields}

    def save(self, table, value, commit=True):
        assert table in CAPS
        value["updated_at"] = time.time()
        with self.store.lock:
            db = self.store.db
            if db.execute(f"SELECT 1 FROM {table} WHERE id=?", (value["id"],)).fetchone() is None:
                if db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] >= CAPS[table]:
                    raise Failure("capacity", "Archive closed bus runs or remove unused profiles to release capacity.", 409)
            db.execute(f"INSERT INTO {table} VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
                       (value["id"], value["actor"], value["key"], value["digest"], json.dumps(value, allow_nan=False)))
            if commit:
                db.commit()

    def delete(self, table, identity):
        assert table in CAPS
        with self.store.lock, self.store.db:
            self.store.db.execute(f"DELETE FROM {table} WHERE id=?", (identity,))


def public(value):
    return {key: content for key, content in value.items() if key not in {
        "actor", "key", "digest", "fingerprint", "authorization", "outbox_acks"}}
