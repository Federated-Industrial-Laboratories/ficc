# SPDX-License-Identifier: Apache-2.0
"""Bounded retained pairing, grant and mutation receipts use the normal state provider."""
import json

from ..errors import Failure

TABLES = {"federation_peers": 128, "federation_offers": 256,
          "federation_grants": 256, "federation_operations": 2048}


def initialize(db):
    for table in TABLES:
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY,project_id TEXT NOT NULL,value TEXT NOT NULL)")


class Records:
    def __init__(self, store, table):
        if table not in TABLES:
            raise ValueError("Unknown federation record kind.")
        self.store, self.table = store, table

    def all(self, project=None):
        with self.store.lock:
            rows = self.store.db.execute(f"SELECT value FROM {self.table}" + (
                " WHERE project_id=:p0" if project else "") + " ORDER BY id",
                (project,) if project else ()).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get(self, identity):
        with self.store.lock:
            row = self.store.db.execute(f"SELECT value FROM {self.table} WHERE id=:p0", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The federation record was not found.", 404)
        return json.loads(row[0])

    def find(self, identity):
        try:
            return self.get(identity)
        except Failure as exc:
            if exc.status == 404:
                return None
            raise

    def save(self, value):
        raw = json.dumps(value, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 1024*1024:
            raise Failure("federation_capacity", "The federation record exceeds 1 MiB.", 409)
        with self.store.lock, self.store.db:
            if self.find(value["id"]) is None:
                count = self.store.db.execute(f"SELECT count(*) FROM {self.table}").fetchone()[0]
                if count >= TABLES[self.table]:
                    raise Failure("federation_capacity", "Remove completed federation records before adding more.", 409)
            self.store.db.execute(f"INSERT INTO {self.table} VALUES (:p0,:p1,:p2) ON CONFLICT(id) DO UPDATE SET project_id=excluded.project_id,value=excluded.value", (value["id"], value["project_id"], raw))

    def remove(self, identity):
        with self.store.lock, self.store.db:
            self.store.db.execute(f"DELETE FROM {self.table} WHERE id=:p0", (identity,))


def suspend(db):
    db.execute("DELETE FROM settings WHERE key='federation.configuration'")
    for table in ("federation_peers", "federation_offers", "federation_grants"):
        for identity, raw in db.execute(f"SELECT id,value FROM {table}").fetchall():
            value = json.loads(raw)
            value["state"] = "suspended"
            db.execute(f"UPDATE {table} SET value=:p0 WHERE id=:p1", (json.dumps(value), identity))


def validate_records(db):
    from .schema import Cluster, GrantSpec, Offer
    projects = {row[0] for row in db.execute("SELECT id FROM projects")}
    for table in TABLES:
        for identity, project, raw in db.execute(f"SELECT * FROM {table}"):
            value = json.loads(raw)
            if value.get("id") != identity or value.get("project_id") != project or project not in projects:
                raise ValueError("Federation metadata has an invalid project binding.")
            if table == "federation_peers":
                Cluster.model_validate(value["cluster"])
            elif table == "federation_offers":
                Offer.model_validate(value["offer"]["payload"])
            elif table == "federation_grants":
                GrantSpec.model_validate(value["spec"])
