# SPDX-License-Identifier: Apache-2.0
"""Issue expiring credentials and enforce grants on each request."""

import hashlib
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from .errors import Failure
from .settings import MAX_NODES, SCOPES
from .store import Store


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass
class Principal:
    id: str
    label: str
    scopes: list[str]
    node_ids: list[str] | None
    csrf: str
    kind: str
    expires_at: float
    root_ids: list[str] | None = None

    def require(self, scope: str, node_id: str | None = None,
                root_id: str | None = None) -> None:
        if scope not in self.scopes or (
            node_id is not None and self.node_ids is not None and node_id not in self.node_ids
        ) or (root_id is not None and (
            (self.root_ids is not None and root_id not in self.root_ids)
            or (node_id is None and self.node_ids is not None)
        )):
            raise Failure("denied", "This credential does not permit the action.", 403)

    def public(self) -> dict:
        return {"id": self.id, "label": self.label, "scopes": self.scopes,
                "node_ids": self.node_ids, "root_ids": self.root_ids}


class Auth:
    def __init__(self, store: Store):
        self.store = store
        self.on_revoke: Callable[[], None] | None = None

    def issue(self, kind: str, label: str = "Local owner", scopes: list[str] | None = None,
              node_ids: list[str] | None = None, lifetime: int = 3600,
              root_ids: list[str] | None = None) -> tuple[str, Principal]:
        scopes = sorted(SCOPES if scopes is None else set(scopes))
        if not scopes or not set(scopes).issubset(SCOPES):
            raise Failure("invalid_scope", "Select supported permission scopes.")
        if not 1 <= lifetime <= 2592000 or not 1 <= len(label) <= 80:
            raise Failure("invalid_credential", "Credential label or lifetime is invalid.")
        if node_ids is not None:
            if len(node_ids) > MAX_NODES or any(not isinstance(n, str) for n in node_ids):
                raise Failure("invalid_nodes", "The machine selection is invalid.")
            for node_id in node_ids:
                self.store.node(node_id)
        if root_ids is not None:
            if len(root_ids) > 64 or any(not isinstance(r, str) for r in root_ids):
                raise Failure("invalid_roots", "The folder selection is invalid.")
            with self.store.lock:
                for root_id in root_ids:
                    if self.store.db.execute("SELECT id FROM file_roots WHERE id=?", (root_id,)).fetchone() is None:
                        raise Failure("invalid_roots", "The registered folder was not found.")
        value = secrets.token_urlsafe(32)
        principal = Principal(secrets.token_hex(16), label, scopes, node_ids,
                              secrets.token_urlsafe(24), kind, time.time() + lifetime, root_ids)
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM credentials WHERE expires < ?", (time.time(),))
            count = self.store.db.execute("SELECT count(*) FROM credentials").fetchone()[0]
            if count >= 512:
                raise Failure("capacity", "The credential limit was reached.", 409)
            self.store.db.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?,?)", (
                principal.id, digest(value), kind, label, json.dumps(scopes),
                json.dumps(node_ids), principal.expires_at, principal.csrf, json.dumps(root_ids)))
        return value, principal

    def resolve(self, value: str, kinds: tuple[str, ...] = ("session", "token"),
                consume: bool = False) -> Principal:
        if not value or len(value) > 128:
            raise Failure("unauthenticated", "Sign in to continue.", 401)
        with self.store.lock, self.store.db:
            row = self.store.db.execute(
                "SELECT id,label,scopes,nodes,csrf,kind,expires,roots FROM credentials WHERE digest=?",
                (digest(value),)).fetchone()
            if row is None or row[5] not in kinds or row[6] <= time.time():
                raise Failure("unauthenticated", "Sign in to continue.", 401)
            if consume:
                self.store.db.execute("DELETE FROM credentials WHERE id=?", (row[0],))
        return Principal(row[0], row[1], json.loads(row[2]), json.loads(row[3]),
                         row[4], row[5], row[6], json.loads(row[7]))

    def revoke(self, credential_id: str, actor: str = "local-owner") -> None:
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
        if self.on_revoke:
            self.on_revoke()
        self.store.audit("credential.revoke", credential_id, actor=actor)

    def current(self, credential_id: str) -> Principal:
        """Read current grants again before a queued operation is dispatched."""
        with self.store.lock:
            row = self.store.db.execute(
                "SELECT id,label,scopes,nodes,csrf,kind,expires,roots FROM credentials WHERE id=?",
                (credential_id,)).fetchone()
        if row is None or row[5] not in ("session", "token") or row[6] <= time.time():
            raise Failure("unauthenticated", "Sign in to continue.", 401)
        return Principal(row[0], row[1], json.loads(row[2]), json.loads(row[3]),
                         row[4], row[5], row[6], json.loads(row[7]))

    def tokens(self) -> list[dict]:
        with self.store.lock:
            rows = self.store.db.execute(
                "SELECT id,label,scopes,nodes,expires,roots FROM credentials "
                "WHERE kind='token' AND expires > ? ORDER BY label", (time.time(),)).fetchall()
        return [{"id": r[0], "label": r[1], "scopes": json.loads(r[2]),
                 "node_ids": json.loads(r[3]), "expires_at": r[4], "root_ids": json.loads(r[5])} for r in rows]
