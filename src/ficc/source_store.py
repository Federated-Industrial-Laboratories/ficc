# SPDX-License-Identifier: Apache-2.0
"""Durable project connections, registered templates and no-replay receipts."""

import json
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .dataset_store import encoded
from .errors import Failure

TABLES = ("source_connections", "source_queries", "source_runs", "source_uploads")
TERMINAL = {"completed", "failed", "cancelled", "unknown"}


def initialize(db):
    for table in TABLES:
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY,subject_id TEXT NOT NULL,"
                   "project_id TEXT NOT NULL,key TEXT NOT NULL,digest TEXT NOT NULL,value TEXT NOT NULL,"
                   "UNIQUE(subject_id,project_id,key))")


class SourceStore:
    def __init__(self, store):
        self.store = store

    def get(self, table, identity):
        assert table in TABLES
        with self.store.lock:
            row = self.store.db.execute(f"SELECT value FROM {table} WHERE id=:p0", (identity,)).fetchone()
        if not row:
            raise Failure("not_found", "The source record was not found.", 404)
        return json.loads(row[0])

    def page(self, table, project, before=None):
        assert table in TABLES
        with self.store.lock:
            rows = self.store.db.execute(f"SELECT value FROM {table} WHERE project_id=:p0 AND id<:p1 ORDER BY id DESC LIMIT 51",
                                         (project, before or "g")).fetchall()
        return [json.loads(row[0]) for row in rows]

    def insert(self, table, value, key, request_digest):
        assert table in TABLES
        with self.store.lock, self.store.db:
            self.store.db.execute(f"INSERT INTO {table} VALUES (:p0,:p1,:p2,:p3,:p4,:p5)",
                (value["id"], value["subject_id"], value["project_id"], key, request_digest, encoded(value).decode()))

    def save(self, table, value):
        assert table in TABLES
        with self.store.lock, self.store.db:
            self.store.db.execute(f"UPDATE {table} SET value=:p0 WHERE id=:p1", (encoded(value).decode(), value["id"]))

    def existing(self, table, principal, key, request_digest):
        assert table in TABLES
        with self.store.lock:
            row = self.store.db.execute(f"SELECT id,digest FROM {table} WHERE subject_id=:p0 AND project_id=:p1 AND key=:p2",
                                         (principal.subject_id, principal.project_id, key)).fetchone()
        if row is None:
            return None
        if row[1] != request_digest:
            raise Failure("idempotency_conflict", "This key belongs to another source request.", 409)
        return self.get(table, row[0])

    def recover(self):
        with self.store.lock, self.store.db:
            after = ""
            while page := self.store.db.execute("SELECT id,value FROM source_runs WHERE id>:p0 ORDER BY id LIMIT 100", (after,)).fetchall():
                for identity, raw in page:
                    value = json.loads(raw)
                    if value["state"] not in TERMINAL:
                        value.update(state="unknown", error={"code": "controller_restart", "message": "The controller stopped before the final receipt. This operation will not be replayed."})
                        self.store.db.execute("UPDATE source_runs SET value=:p0 WHERE id=:p1", (encoded(value).decode(), identity))
                        if value.get("upload_id"):
                            upload = self.get("source_uploads", value["upload_id"])
                            upload["state"] = "unknown"
                            self.save("source_uploads", upload)
                    after = identity

    @contextmanager
    def part_receipts(self, upload):
        """Mount a bounded derived view of durable acknowledgements, never a control array."""
        latest: dict[int, tuple[tuple[float, str], dict]] = {}
        after = ""
        while True:
            with self.store.lock:
                page = self.store.db.execute("SELECT id,value FROM source_runs WHERE project_id=:p0 AND id>:p1 ORDER BY id LIMIT 100",
                                             (upload["project_id"], after)).fetchall()
            if not page:
                break
            for identity, raw in page:
                value = json.loads(raw)
                receipt = value.get("receipt", {})
                number = receipt.get("part_number")
                if (value.get("upload_id") == upload["id"] and value["state"] == "completed" and value.get("operation") == "part"
                        and receipt.get("outcome") == "part_uploaded" and type(number) is int and 1 <= number <= 10000):
                    stamp = (value["finished_at"], identity)
                    if number not in latest or stamp > latest[number][0]:
                        latest[number] = (stamp, {key: receipt[key] for key in ("part_number", "size", "checksum_sha256", "etag")})
                after = identity
        with tempfile.TemporaryDirectory(prefix="ficc-source-receipts-") as directory:
            path = Path(directory) / "parts.ndjson"
            with path.open("wb") as stream:
                for number in sorted(latest):
                    stream.write(encoded(latest[number][1]) + b"\n")
            yield str(path)


def validate_records(db, *, quiescent=True):
    from .source_schema import RegisteredQuery
    users = {row[0] for row in db.execute("SELECT id FROM identities")}
    projects = {row[0] for row in db.execute("SELECT id FROM projects")}
    for table in TABLES:
        for identity, subject, project, raw in db.execute(f"SELECT id,subject_id,project_id,value FROM {table}"):
            value = json.loads(raw)
            if (len(raw) > 262144 or (value["id"], value["subject_id"], value["project_id"]) != (identity, subject, project)
                    or subject not in users or project not in projects):
                raise ValueError("A source record is invalid.")
            if table == "source_queries":
                RegisteredQuery.model_validate(value["query"])
            if table == "source_runs" and quiescent and value["state"] not in TERMINAL:
                raise ValueError("Wait for source operations to finish before backup.")
