# SPDX-License-Identifier: Apache-2.0
"""Bind verified external subjects to explicitly approved local identities."""

import re
import secrets

from .errors import Failure
from .identity_store import LOCAL_OWNER, Identities
from .remote_settings import https_url


def initialize(db) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS external_identities (id TEXT PRIMARY KEY, "
               "issuer TEXT NOT NULL, external_subject TEXT NOT NULL, subject_id TEXT NOT NULL REFERENCES identities(id), "
               "disabled INTEGER NOT NULL, revision INTEGER NOT NULL, UNIQUE(issuer,external_subject))")


def subject(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 255
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("Use an external subject identifier of 1 to 255 characters.")
    return value


def public(row):
    return {"id": row[0], "issuer": row[1], "external_subject": row[2], "subject_id": row[3],
            "disabled": bool(row[4]), "revision": row[5]}


class ExternalIdentities:
    def __init__(self, store):
        self.store = store

    def all(self):
        with self.store.lock:
            return [public(row) for row in self.store.db.execute("SELECT * FROM external_identities ORDER BY id")]

    def find(self, issuer, external_subject):
        with self.store.lock:
            row = self.store.db.execute("SELECT * FROM external_identities WHERE issuer=:p0 AND external_subject=:p1",
                                        (issuer, external_subject)).fetchone()
        return public(row) if row else None

    def save(self, issuer, external_subject, subject_id, disabled, revision, actor=None):
        try:
            https_url(issuer)
            subject(external_subject)
        except ValueError as exc:
            raise Failure("invalid_identity", str(exc)) from None
        if (subject_id == LOCAL_OWNER or not isinstance(subject_id, str) or not re.fullmatch(r"[0-9a-f]{32}", subject_id)
                or type(disabled) is not bool or type(revision) is not int or revision < 0):
            raise Failure("invalid_identity", "Select a member identity and its current mapping revision.")
        with self.store.lock, self.store.db:
            Identities(self.store).user(subject_id)
            before = self.find(issuer, external_subject)
            if (before["revision"] if before else 0) != revision:
                raise Failure("revision_conflict", "The external identity mapping changed. Reload it before saving.", 409)
            if not before and self.store.db.execute("SELECT count(*) FROM external_identities").fetchone()[0] >= 1024:
                raise Failure("capacity", "The external identity mapping limit was reached.", 409)
            identity = before["id"] if before else secrets.token_hex(16)
            self.store.db.execute("INSERT INTO external_identities VALUES (:p0,:p1,:p2,:p3,:p4,:p5) "
                                  "ON CONFLICT(issuer,external_subject) DO UPDATE SET subject_id=excluded.subject_id,"
                                  "disabled=excluded.disabled,revision=excluded.revision",
                                  (identity, issuer, external_subject, subject_id, int(disabled), revision + 1))
            self.store.audit("identity.external", identity, actor=actor.id if actor else "local-owner",
                             subject_id=actor.subject_id if actor else LOCAL_OWNER,
                             project_id=actor.project_id if actor else None)
            return self.find(issuer, external_subject)


def validate_records(db):
    from .backup_identities import identity
    users = {row[0] for row in db.execute("SELECT id FROM identities")}
    seen = set()
    for row in db.execute("SELECT * FROM external_identities"):
        identity(row[0])
        https_url(row[1])
        subject(row[2])
        if (row[3] not in users or row[3] == LOCAL_OWNER or row[4] not in (0, 1)
                or type(row[5]) is not int or row[5] < 1 or (row[1], row[2]) in seen):
            raise ValueError("An external identity mapping is invalid.")
        seen.add((row[1], row[2]))
