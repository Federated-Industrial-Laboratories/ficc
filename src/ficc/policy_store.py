# SPDX-License-Identifier: Apache-2.0
"""Persist policy publishers, signed packages, role bindings, and activation revisions."""

import hashlib
import json
import time
from typing import Any

from .errors import Failure
from .identity_store import Identities
from .policy_packages import HASH, identifier, inspect, public_key, verify

STATE_KEY = "policy_state"
DEFAULT: dict[str, Any] = {"revision": 0, "required": False, "active": None, "previous": None, "history": []}


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS policy_publishers (id TEXT PRIMARY KEY, public_key TEXT NOT NULL, "
               "enabled INTEGER NOT NULL, revision INTEGER NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS policy_packages (digest TEXT PRIMARY KEY, publisher TEXT NOT NULL, "
               "description TEXT NOT NULL, archive BLOB NOT NULL, installed REAL NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS policy_bindings (project_id TEXT NOT NULL REFERENCES projects(id), "
               "subject_id TEXT NOT NULL REFERENCES identities(id), roles TEXT NOT NULL, revision INTEGER NOT NULL, "
               "PRIMARY KEY(project_id,subject_id))")


def revision(value):
    if type(value) is not int or not 0 <= value < 2**53 - 1:
        raise ValueError("The policy revision is invalid.")
    return value


def state_value(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT) or type(value["required"]) is not bool:
        raise ValueError("The policy state is invalid.")
    revision(value["revision"])
    for name in ("active", "previous"):
        if value[name] is not None and (not isinstance(value[name], str) or not HASH.fullmatch(value[name])):
            raise ValueError("The policy package reference is invalid.")
    if value["active"] and not value["required"]:
        raise ValueError("An active policy must require enforcement.")
    if not isinstance(value["history"], list) or len(value["history"]) > 64:
        raise ValueError("The policy history is invalid.")
    for item in value["history"]:
        if (not isinstance(item, dict) or set(item) != {"revision", "digest"}
                or not isinstance(item["digest"], str) or not HASH.fullmatch(item["digest"])
                or not 1 <= revision(item["revision"]) <= value["revision"]):
            raise ValueError("A policy history entry is invalid.")
    return value


def role_ids(roles):
    if not isinstance(roles, list) or len(roles) > 64:
        raise ValueError("Select at most 64 distinct policy roles.")
    for role in roles:
        identifier(role)
    if len(set(roles)) != len(roles):
        raise ValueError("Select distinct policy roles.")
    return sorted(roles)


class PolicyStore:
    def __init__(self, store):
        self.store = store

    def state(self):
        return state_value(self.store.get_setting(STATE_KEY, dict(DEFAULT)))

    def bump(self):
        value = self.state()
        value["revision"] = revision(value["revision"]) + 1
        self.store.set_setting(STATE_KEY, value)
        return value

    def publishers(self):
        with self.store.lock:
            return [{"id": row[0], "public_key": row[1], "fingerprint": public_key(row[1])[1],
                     "enabled": bool(row[2]), "revision": row[3]}
                    for row in self.store.db.execute("SELECT id,public_key,enabled,revision FROM policy_publishers ORDER BY id")]

    def publisher(self, identity):
        identifier(identity)
        value = next((item for item in self.publishers() if item["id"] == identity), None)
        if value is None or not value["enabled"]:
            raise Failure("policy_publisher_untrusted", "The policy publisher is not trusted.", 403)
        return value

    def trust(self, identity, key, enabled, expected):
        identifier(identity)
        key, _ = public_key(key)
        if type(enabled) is not bool:
            raise ValueError("The policy trust state is invalid.")
        revision(expected)
        with self.store.lock, self.store.db:
            old = next((item for item in self.publishers() if item["id"] == identity), None)
            if (old["revision"] if old else 0) != expected:
                raise Failure("revision_conflict", "Publisher trust changed. Reload it before saving.", 409)
            if old and old["public_key"] != key:
                raise Failure("policy_key_changed", "Use a new publisher identifier for a different key.", 409)
            if not old and len(self.publishers()) >= 64:
                raise Failure("capacity", "The policy publisher limit was reached.", 409)
            self.store.db.execute("INSERT INTO policy_publishers VALUES (:p0,:p1,:p2,:p3) ON CONFLICT(id) "
                                  "DO UPDATE SET enabled=excluded.enabled,revision=excluded.revision",
                                  (identity, key, int(enabled), expected + 1))
            self.bump()
            return next(item for item in self.publishers() if item["id"] == identity)

    def packages(self):
        with self.store.lock:
            return [{"digest": row[0], "publisher": row[1], "manifest": json.loads(row[2]), "installed_at": row[3]}
                    for row in self.store.db.execute("SELECT digest,publisher,description,installed FROM policy_packages ORDER BY installed,digest")]

    def package(self, digest):
        if not isinstance(digest, str) or not HASH.fullmatch(digest):
            raise ValueError("The policy package digest is invalid.")
        with self.store.lock:
            row = self.store.db.execute("SELECT archive FROM policy_packages WHERE digest=:p0", (digest,)).fetchone()
        if row is None:
            raise Failure("not_found", "The policy package was not found.", 404)
        raw = bytes(row[0])
        if hashlib.sha256(raw).hexdigest() != digest:
            raise Failure("policy_changed", "The stored policy package does not match its digest.", 409)
        value, _, _, _ = inspect(raw)
        publisher = self.publisher(value["publisher"])
        value, _, payload = verify(raw, publisher["public_key"])
        return value, payload, publisher

    def install(self, raw):
        value, _, _, _ = inspect(raw)
        publisher = self.publisher(value["publisher"])
        value, _, _ = verify(raw, publisher["public_key"])
        digest = hashlib.sha256(raw).hexdigest()
        with self.store.lock, self.store.db:
            if self.publisher(value["publisher"]) != publisher:
                raise Failure("revision_conflict", "Publisher trust changed during package inspection.", 409)
            existing = next((item for item in self.packages() if item["digest"] == digest), None)
            if existing:
                return existing
            if len(self.packages()) >= 64:
                raise Failure("capacity", "The policy package limit was reached.", 409)
            self.store.db.execute("INSERT INTO policy_packages VALUES (:p0,:p1,:p2,:p3,:p4)",
                                  (digest, value["publisher"], json.dumps(value), raw, time.time()))
        return next(item for item in self.packages() if item["digest"] == digest)

    def bindings(self, project):
        Identities(self.store).project(project)
        with self.store.lock:
            return [{"subject_id": row[0], "roles": role_ids(json.loads(row[1])), "revision": row[2]}
                    for row in self.store.db.execute("SELECT subject_id,roles,revision FROM policy_bindings "
                                                     "WHERE project_id=:p0 ORDER BY subject_id", (project,))]

    def roles(self, project, subject):
        with self.store.lock:
            row = self.store.db.execute("SELECT roles FROM policy_bindings WHERE project_id=:p0 AND subject_id=:p1",
                                        (project, subject)).fetchone()
        return role_ids(json.loads(row[0])) if row else []

    def bind(self, project, subject, roles, expected):
        roles = role_ids(roles)
        revision(expected)
        with self.store.lock, self.store.db:
            Identities(self.store).access(subject, project)
            old = next((item for item in self.bindings(project) if item["subject_id"] == subject), None)
            if (old["revision"] if old else 0) != expected:
                raise Failure("revision_conflict", "Policy roles changed. Reload them before saving.", 409)
            if not old and self.store.db.execute("SELECT count(*) FROM policy_bindings").fetchone()[0] >= 4096:
                raise Failure("capacity", "The policy role binding limit was reached.", 409)
            self.store.db.execute("INSERT INTO policy_bindings VALUES (:p0,:p1,:p2,:p3) "
                                  "ON CONFLICT(project_id,subject_id) DO UPDATE SET roles=excluded.roles,revision=excluded.revision",
                                  (project, subject, json.dumps(roles), expected + 1))
            self.bump()
        return {"subject_id": subject, "roles": roles, "revision": expected + 1}

    def activate(self, digest, expected):
        with self.store.lock, self.store.db:
            value = self.state()
            if value["revision"] != revision(expected):
                raise Failure("revision_conflict", "Policy state changed. Reload it before activation.", 409)
            value.update(revision=expected + 1, required=True, previous=value["active"], active=digest)
            value["history"] = (value["history"] + [{"revision": value["revision"], "digest": digest}])[-64:]
            self.store.set_setting(STATE_KEY, state_value(value))
            return value
