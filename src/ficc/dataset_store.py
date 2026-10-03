# SPDX-License-Identifier: Apache-2.0
"""Retain immutable project manifests with authenticated source references."""

import hashlib
import hmac
import json

from ficc_node.file_access import parts

from .dataset_schema import DataSchema, Provenance
from .errors import Failure
from .file_numbers import integer

MAX_MANIFEST = 262144


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS datasets (id TEXT PRIMARY KEY,subject_id TEXT NOT NULL,"
               "project_id TEXT NOT NULL,key TEXT NOT NULL,digest TEXT NOT NULL,value TEXT NOT NULL,"
               "UNIQUE(subject_id,project_id,key))")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def seal(value, key):
    raw = encoded(value)
    if len(raw) > MAX_MANIFEST:
        raise Failure("manifest_limit", "The dataset manifest exceeds 256 KiB.", 413)
    return {**value, "manifest_digest": hashlib.sha256(raw).hexdigest(),
            "authentication": hmac.digest(key, b"ficc-dataset-v1\0" + raw, "sha256").hex()}


def verify(value, key):
    raw = encoded({name: item for name, item in value.items() if name not in {"manifest_digest", "authentication"}})
    if (len(raw) > MAX_MANIFEST or value["version"] != 1
            or hashlib.sha256(raw).hexdigest() != value["manifest_digest"]
            or not hmac.compare_digest(hmac.digest(key, b"ficc-dataset-v1\0" + raw, "sha256").hex(), value["authentication"])):
        raise ValueError("The dataset manifest failed authentication.")
    DataSchema.model_validate(value["schema"])
    Provenance.model_validate(value["provenance"])
    if "origin" in value and (not isinstance(value["origin"], dict) or len(encoded(value["origin"])) > 32768):
        raise ValueError("The dataset origin is invalid.")
    if not 1 <= len(value["files"]) <= 128:
        raise ValueError("The dataset file count is invalid.")
    for source in value["files"]:
        parts(source["reference"])
        if (integer(source["size"]) != source["reference"]["identity"]["size"]
                or len(source["sha256"]) != 64 or any(char not in "0123456789abcdef" for char in source["sha256"])):
            raise ValueError("The dataset file digest or size is invalid.")
    return value


class DatasetStore:
    def __init__(self, store, key):
        self.store, self.key = store, key

    def decoded(self, row):
        value = verify(json.loads(row[3]), self.key)
        if (value["id"], value["subject_id"], value["project_id"]) != tuple(row[:3]):
            raise ValueError("The dataset manifest ownership differs from its record.")
        return value

    def get(self, identity):
        with self.store.lock:
            row = self.store.db.execute("SELECT id,subject_id,project_id,value FROM datasets WHERE id=:p0", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The dataset was not found.", 404)
        return self.decoded(row)

    def iterate(self, project, before=None):
        before = before or "g"
        while True:
            with self.store.lock:
                row = self.store.db.execute("SELECT id,subject_id,project_id,value FROM datasets WHERE project_id=:p0 AND id<:p1 ORDER BY id DESC LIMIT 1", (project, before)).fetchone()
            if row is None:
                return
            before = row[0]
            yield self.decoded(row)

    def existing(self, subject, project, key, request_digest):
        with self.store.lock:
            row = self.store.db.execute("SELECT id,digest FROM datasets WHERE subject_id=:p0 AND project_id=:p1 AND key=:p2", (subject, project, key)).fetchone()
        if row is None:
            return None
        if row[1] != request_digest:
            raise Failure("idempotency_conflict", "This key belongs to another dataset request.", 409)
        return self.get(row[0])

    def insert(self, value, key, request_digest):
        self.store.db.execute("INSERT INTO datasets VALUES (:p0,:p1,:p2,:p3,:p4,:p5)",
            (value["id"], value["subject_id"], value["project_id"], key, request_digest, encoded(value).decode()))


def validate_records(db):
    rows = db.execute("SELECT id,subject_id,project_id,value FROM datasets").fetchall()
    if not rows:
        return
    row = db.execute("SELECT value FROM settings WHERE key='file_reference_key'").fetchone()
    key = bytes.fromhex(json.loads(row[0])) if row else b""
    users = {row[0] for row in db.execute("SELECT id FROM identities")}
    projects = {row[0] for row in db.execute("SELECT id FROM projects")}
    for identity, subject, project, raw in rows:
        value = verify(json.loads(raw), key)
        if (value["id"], value["subject_id"], value["project_id"]) != (identity, subject, project) or subject not in users or project not in projects:
            raise ValueError("The dataset owner or project is invalid.")
