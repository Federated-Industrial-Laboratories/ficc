# SPDX-License-Identifier: Apache-2.0
"""Validate portable policy records and suspend authority after restoration."""

import hashlib
import json

from .policy_packages import identifier, inspect, public_key
from .policy_store import DEFAULT, STATE_KEY, revision, role_ids, state_value


def records(db):
    publishers = set()
    for identity, key, enabled, current in db.execute("SELECT id,public_key,enabled,revision FROM policy_publishers"):
        identifier(identity)
        public_key(key)
        if type(enabled) is not int or enabled not in (0, 1) or revision(current) < 1:
            raise ValueError("A policy publisher record is invalid.")
        publishers.add(identity)
    packages = set()
    for digest, publisher, description, archive, installed in db.execute(
            "SELECT digest,publisher,description,archive,installed FROM policy_packages"):
        if not isinstance(archive, bytes) or hashlib.sha256(archive).hexdigest() != digest:
            raise ValueError("A stored policy archive digest is invalid.")
        value, _, _, _ = inspect(archive)
        if (publisher not in publishers or publisher != value["publisher"] or json.loads(description) != value
                or not isinstance(installed, (float, int)) or not 0 <= installed < 2**53):
            raise ValueError("A stored policy package record is invalid.")
        packages.add(digest)
    projects = {row[0] for row in db.execute("SELECT id FROM projects")}
    users = {row[0] for row in db.execute("SELECT id FROM identities")}
    for project, subject, roles, current in db.execute("SELECT project_id,subject_id,roles,revision FROM policy_bindings"):
        role_ids(json.loads(roles))
        if project not in projects or subject not in users or revision(current) < 1:
            raise ValueError("A policy role binding is invalid.")
    row = db.execute("SELECT value FROM settings WHERE key=:p0", (STATE_KEY,)).fetchone()
    if row:
        value = state_value(json.loads(row[0]))
        references = {item["digest"] for item in value["history"]} | {value["active"], value["previous"]}
        if references - packages - {None}:
            raise ValueError("A policy activation references a missing package.")


def deactivate(db):
    row = db.execute("SELECT value FROM settings WHERE key=:p0", (STATE_KEY,)).fetchone()
    if row:
        value = state_value(json.loads(row[0]))
        value.update(active=None, previous=None, revision=revision(value["revision"]) + 1)
        db.execute("UPDATE settings SET value=:p0 WHERE key=:p1", (json.dumps(value), STATE_KEY))
    elif db.execute("SELECT count(*) FROM policy_packages").fetchone()[0]:
        value = {**DEFAULT, "required": True, "revision": 1}
        db.execute("INSERT INTO settings VALUES (:p0,:p1)", (STATE_KEY, json.dumps(value)))
    db.execute("UPDATE policy_publishers SET enabled=0,revision=revision+1")
