# SPDX-License-Identifier: Apache-2.0
"""Retain safety policy separately from immutable bytes and scanner receipts."""

import hashlib
import json
import re

from .dataset_store import encoded
from .errors import Failure
from .inspection_sdk import OUTCOMES


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS dataset_safety (id TEXT PRIMARY KEY,value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS dataset_lineage (dataset_id TEXT NOT NULL,parent_id TEXT NOT NULL,PRIMARY KEY(dataset_id,parent_id))")
    db.execute("CREATE TABLE IF NOT EXISTS dataset_objects (dataset_id TEXT NOT NULL,project_id TEXT NOT NULL,kind TEXT NOT NULL,"
               "path_key TEXT NOT NULL,sha256 TEXT NOT NULL,bytes BIGINT NOT NULL,PRIMARY KEY(dataset_id,kind,path_key,sha256))")
    db.execute("CREATE INDEX IF NOT EXISTS dataset_objects_path ON dataset_objects(project_id,path_key)")
    db.execute("CREATE INDEX IF NOT EXISTS dataset_objects_digest ON dataset_objects(project_id,sha256,bytes)")
    db.execute("CREATE TABLE IF NOT EXISTS inspection_runs (id TEXT PRIMARY KEY,subject_id TEXT NOT NULL,project_id TEXT NOT NULL,"
               "dataset_id TEXT NOT NULL,key TEXT NOT NULL,digest TEXT NOT NULL,value TEXT NOT NULL,UNIQUE(subject_id,project_id,key))")
    db.execute("CREATE TABLE IF NOT EXISTS inspection_files (run_id TEXT NOT NULL,file_index INTEGER NOT NULL,value TEXT NOT NULL,PRIMARY KEY(run_id,file_index))")


def default(identity):
    return {"id": identity, "revision": 1, "sensitive": False, "inspection_required": False,
            "quarantined": False, "exemption": None, "latest_run": None}


def object_key(source):
    return hashlib.sha256(encoded({"root_id": source["root_id"], "parts": source["reference"]["parts"]})).hexdigest()


def parents(value):
    parents = set(value["provenance"]["input_dataset_ids"])
    if value.get("previous_version_id"):
        parents.add(value["previous_version_id"])
    origin = value.get("origin", {})
    if origin.get("kind") == "workload" and origin.get("input_dataset"):
        parents.add(origin["input_dataset"]["id"])
    return parents


def index(db, value, inputs=()):
    for parent in parents(value):
        db.execute("INSERT INTO dataset_lineage VALUES (:p0,:p1) ON CONFLICT DO NOTHING", (value["id"], parent))
    for kind, sources in (("output", value["files"]), ("input", inputs)):
        for source in sources:
            # Connection capabilities bind a path/inode, not a complete digest.
            # An empty digest explicitly records path-only lineage for that input.
            digest = source["sha256"] if kind == "output" else source.get("sha256", "")
            size = source["size"] if "size" in source else source["reference"]["identity"]["size"]
            db.execute("INSERT INTO dataset_objects VALUES (:p0,:p1,:p2,:p3,:p4,:p5) ON CONFLICT DO NOTHING",
                (value["id"], value["project_id"], kind, object_key(source), digest, size))


def backfill(db):
    after = ""
    while page := db.execute("SELECT id,value FROM datasets WHERE id>:p0 ORDER BY id LIMIT 100", (after,)).fetchall():
        for identity, raw in page:
            value = json.loads(raw)
            inputs = []
            origin = value.get("origin", {})
            if origin.get("kind") == "query" and origin.get("connection_id"):
                connection = db.execute("SELECT value FROM source_connections WHERE id=:p0", (origin["connection_id"],)).fetchone()
                source = json.loads(connection[0]).get("source") if connection else None
                if source:
                    inputs.append(source)
            index(db, value, inputs)
            after = identity


class InspectionStore:
    def __init__(self, store):
        self.store = store

    def policy(self, identity):
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM dataset_safety WHERE id=:p0", (identity,)).fetchone()
        return json.loads(row[0]) if row else default(identity)

    def policy_save(self, value):
        self.store.db.execute("INSERT INTO dataset_safety VALUES (:p0,:p1) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
                              (value["id"], encoded(value).decode()))

    def run(self, identity):
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM inspection_runs WHERE id=:p0", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The inspection was not found.", 404)
        return json.loads(row[0])

    def save(self, value):
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE inspection_runs SET value=:p0 WHERE id=:p1", (encoded(value).decode(), value["id"]))

    def files(self, identity, after=-1):
        with self.store.lock:
            page = self.store.db.execute("SELECT file_index,value FROM inspection_files WHERE run_id=:p0 AND file_index>:p1 ORDER BY file_index LIMIT 21",
                                         (identity, after)).fetchall()
        return {"files": [json.loads(raw) for _, raw in page[:20]], "next_cursor": page[19][0] if len(page) > 20 else None}

    def ancestors(self, value):
        # UNION, rather than UNION ALL, closes aliases/cycles without a recursion cap.
        # Only this project's known byte/path bindings can contribute safety.
        query = """SELECT d.id,s.value FROM (WITH RECURSIVE ancestors(id) AS (
            SELECT :p0
            UNION
            SELECT edges.parent_id FROM ancestors JOIN (
                SELECT dataset_id,parent_id FROM dataset_lineage
                UNION
                SELECT a.dataset_id,b.dataset_id FROM dataset_objects a JOIN dataset_objects b
                ON a.project_id=b.project_id AND b.kind='output' AND
                   (a.path_key=b.path_key OR (a.sha256<>'' AND a.sha256=b.sha256 AND a.bytes=b.bytes))
                WHERE a.project_id=:p1 AND a.dataset_id<>b.dataset_id
            ) edges ON edges.dataset_id=ancestors.id
        ) SELECT id FROM ancestors) ancestors JOIN datasets d ON d.id=ancestors.id
          LEFT JOIN dataset_safety s ON s.id=d.id WHERE d.project_id=:p1 ORDER BY d.id"""
        with self.store.lock:
            cursor = self.store.db.execute(query, (value["id"], value["project_id"]))
            while row := cursor.fetchone():
                yield json.loads(row[1]) if row[1] else default(row[0])

    def recover(self):
        with self.store.lock, self.store.db:
            after = ""
            while page := self.store.db.execute("SELECT id,value FROM inspection_runs WHERE id>:p0 ORDER BY id LIMIT 100", (after,)).fetchall():
                for identity, raw in page:
                    value = json.loads(raw)
                    if value["state"] != "completed":
                        value.update(state="completed", outcome="incomplete", reason="controller_restart")
                        self.save(value)
                    after = identity


def validate_records(db):
    for identity, project, raw in db.execute("SELECT id,project_id,value FROM datasets"):
        value = json.loads(raw)
        actual = set(db.execute("SELECT parent_id FROM dataset_lineage WHERE dataset_id=:p0", (identity,)).fetchall())
        if actual != {(parent,) for parent in parents(value)}:
            raise ValueError("The dataset safety lineage is incomplete.")
        actual = set(db.execute("SELECT project_id,path_key,sha256,bytes FROM dataset_objects WHERE dataset_id=:p0 AND kind='output'", (identity,)).fetchall())
        if actual != {(project, object_key(source), source["sha256"], source["size"]) for source in value["files"]}:
            raise ValueError("The dataset safety file index is incomplete.")
    for identity, project, kind, path, digest, size in db.execute("SELECT dataset_id,project_id,kind,path_key,sha256,bytes FROM dataset_objects"):
        if (kind not in {"input", "output"} or not re.fullmatch("[a-f0-9]{64}", path)
                or not (kind == "input" and digest == "" or re.fullmatch("[a-f0-9]{64}", digest))
                or type(size) is not int or size < 0
                or db.execute("SELECT id FROM datasets WHERE id=:p0 AND project_id=:p1", (identity, project)).fetchone() is None):
            raise ValueError("The dataset safety file index is invalid.")
    for identity, raw in db.execute("SELECT id,value FROM dataset_safety"):
        value = json.loads(raw)
        if (value["id"] != identity or type(value["revision"]) is not int or value["revision"] < 1
                or any(type(value[name]) is not bool for name in ("sensitive", "inspection_required", "quarantined"))
                or db.execute("SELECT id FROM datasets WHERE id=:p0", (identity,)).fetchone() is None):
            raise ValueError("The dataset safety policy is invalid.")
        if value["latest_run"] and db.execute("SELECT id FROM inspection_runs WHERE id=:p0 AND dataset_id=:p1", (value["latest_run"], identity)).fetchone() is None:
            raise ValueError("The dataset safety inspection binding is invalid.")
        if value["exemption"]:
            exemption = value["exemption"]
            if (not re.fullmatch("[a-f0-9]{64}", exemption["basis_digest"]) or not isinstance(exemption["reason"], str)
                    or not 1 <= len(exemption["reason"]) <= 1024
                    or (exemption["expires_at"] is not None and type(exemption["expires_at"]) not in {float, int})):
                raise ValueError("The dataset safety exemption is invalid.")
    for child, parent in db.execute("SELECT dataset_id,parent_id FROM dataset_lineage"):
        rows = db.execute("SELECT project_id FROM datasets WHERE id=:p0 OR id=:p1", (child, parent)).fetchall()
        if len(rows) != 2 or rows[0][0] != rows[1][0]:
            raise ValueError("The dataset safety lineage is invalid.")
    for identity, subject, project, dataset, raw in db.execute("SELECT id,subject_id,project_id,dataset_id,value FROM inspection_runs"):
        value = json.loads(raw)
        if (len(raw) > 65536 or (identity, subject, project, dataset) != tuple(value[key] for key in ("id", "subject_id", "project_id", "dataset_id"))
                or value["state"] != "completed"):
            raise ValueError("Wait for bounded inspection operations to finish before backup.")
        manifest = db.execute("SELECT value FROM datasets WHERE id=:p0 AND project_id=:p1", (dataset, project)).fetchone()
        if manifest is None or json.loads(manifest[0])["manifest_digest"] != value["manifest_digest"]:
            raise ValueError("The inspection manifest binding is invalid.")
        size = len(json.loads(manifest[0])["files"])
        completed = db.execute("SELECT COUNT(*) FROM inspection_files WHERE run_id=:p0", (identity,)).fetchone()[0]
        if (value["outcome"] not in OUTCOMES or value["total_files"] != size or value["completed_files"] != completed
                or not 0 <= completed <= size or (value["outcome"] == "no_detection" and completed != size)):
            raise ValueError("The inspection completion is invalid.")
    for run, number, raw in db.execute("SELECT run_id,file_index,value FROM inspection_files"):
        value = json.loads(raw)
        row = db.execute("SELECT d.value,r.value FROM datasets d JOIN inspection_runs r ON r.dataset_id=d.id WHERE r.id=:p0", (run,)).fetchone()
        if len(raw) > 65536 or value["file_index"] != number or row is None:
            raise ValueError("The inspection file receipt is invalid.")
        files, inspection = json.loads(row[0])["files"], json.loads(row[1])
        if (not 0 <= number < len(files) or value["outcome"] not in OUTCOMES
                or (value["sha256"], value["bytes"]) != (files[number]["sha256"], files[number]["size"])
                or (inspection["outcome"] == "no_detection" and value["outcome"] != "no_detection")):
            raise ValueError("The inspection file receipt is invalid.")
