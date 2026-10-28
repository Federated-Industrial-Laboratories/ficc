# SPDX-License-Identifier: Apache-2.0
"""Portable project metadata for immutable models and persistent services."""
import json

from ..errors import Failure


def initialize(db):
    for table in ("model_revisions", "inference_services"):
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY,project_id TEXT NOT NULL,value TEXT NOT NULL)")


class Records:
    def __init__(self, store, table):
        if table not in {"model_revisions", "inference_services"}:
            raise ValueError("Unknown inference record kind.")
        self.store, self.table = store, table

    def all(self, project=None):
        with self.store.lock:
            rows = self.store.db.execute(f"SELECT value FROM {self.table}" + (" WHERE project_id=:p0" if project else "") + " ORDER BY id", (project,) if project else ()).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get(self, identity):
        with self.store.lock:
            row = self.store.db.execute(f"SELECT value FROM {self.table} WHERE id=:p0", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The model or inference service was not found.", 404)
        return json.loads(row[0])

    def save(self, value):
        with self.store.lock, self.store.db:
            exists = self.store.db.execute(f"SELECT id FROM {self.table} WHERE id=:p0", (value["id"],)).fetchone()
            maximum = 4096 if self.table == "model_revisions" else 2048
            if exists is None and self.store.db.execute(f"SELECT count(*) FROM {self.table}").fetchone()[0] >= maximum:
                raise Failure("capacity", "Remove unused model or service records before adding more.", 409)
            self.store.db.execute(f"INSERT INTO {self.table} VALUES (:p0,:p1,:p2) ON CONFLICT(id) DO UPDATE SET value=excluded.value", (value["id"], value["project_id"], json.dumps(value, separators=(",", ":"))))

    def remove(self, identity):
        with self.store.lock, self.store.db:
            self.store.db.execute(f"DELETE FROM {self.table} WHERE id=:p0", (identity,))


def validate_records(db):
    from ..execution.spec import digest
    from ..models.schema import Record as ModelRecord
    from .schema import Record as ServiceRecord
    projects = {row[0] for row in db.execute("SELECT id FROM projects")}
    for table, schema in (("model_revisions", ModelRecord), ("inference_services", ServiceRecord)):
        for identity, project, raw in db.execute(f"SELECT * FROM {table}"):
            value = schema.model_validate_json(raw)
            if (identity, project) != (value.id, value.project_id) or project not in projects:
                raise ValueError("Inference metadata has an invalid project binding.")
            if isinstance(value, ModelRecord) and value.manifest_digest != digest(value.manifest.model_dump()):
                raise ValueError("The immutable model manifest digest is invalid.")


def suspend(db):
    db.execute("DELETE FROM settings WHERE key IN ('models.directory','models.directory_binding','inference.endpoint_profiles')")
    for identity, raw in db.execute("SELECT id,value FROM inference_services").fetchall():
        value = json.loads(raw)
        value.update(desired="stopped", state="blocked", reason="restored_requires_reconciliation")
        db.execute("UPDATE inference_services SET value=:p0 WHERE id=:p1", (json.dumps(value), identity))
