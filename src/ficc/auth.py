# SPDX-License-Identifier: Apache-2.0
"""Issue expiring credentials and enforce grants on each request."""

import hashlib
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .errors import Failure
from .identity_store import LOCAL_OWNER, LOCAL_PROJECT, PROJECT_SCOPES, Identities
from .resource_store import Resources
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

    subject_id: str = LOCAL_OWNER
    project_id: str = LOCAL_PROJECT
    project_nodes: list[str] = field(default_factory=list)
    project_roots: list[str] = field(default_factory=list)
    policy_check: Callable | None = field(default=None, repr=False, compare=False)

    @property
    def local_owner(self) -> bool:
        return self.subject_id == LOCAL_OWNER

    def permits_node(self, node_id: str) -> bool:
        return ((self.node_ids is None or node_id in self.node_ids)
                and (self.local_owner or node_id in self.project_nodes))

    def effective(self, kind: str) -> list[str] | None:
        ceiling = self.node_ids if kind == "nodes" else self.root_ids
        assigned = self.project_nodes if kind == "nodes" else self.project_roots
        if self.local_owner:
            return ceiling
        return sorted(set(assigned) if ceiling is None else set(assigned) & set(ceiling))

    def sees_record(self, value: dict, *, private: bool = False) -> bool:
        return value.get("project_id") == self.project_id and (
            not private or self.local_owner or value.get("subject_id") == self.subject_id)

    def require_record(self, value: dict, *, private: bool = False) -> None:
        if not self.sees_record(value, private=private):
            raise Failure("not_found", "The operation was not found.", 404)

    def require(self, scope: str, node_id: str | None = None,
                root_id: str | None = None) -> None:
        self.require_host(scope, node_id, root_id)
        if self.policy_check is not None:
            self.policy_check(self, scope, node_id, root_id)

    def permits(self, scope: str, node_id: str | None = None,
                root_id: str | None = None) -> bool:
        try:
            self.require(scope, node_id, root_id)
        except Failure as exc:
            if exc.status != 403:
                raise
            return False
        return True

    def require_host(self, scope: str, node_id: str | None = None,
                     root_id: str | None = None) -> None:
        if scope not in self.scopes or (
            node_id is not None and not self.permits_node(node_id)
        ) or (root_id is not None and (
            (self.root_ids is not None and root_id not in self.root_ids)
            or (node_id is None and self.node_ids is not None)
            or (not self.local_owner and root_id not in self.project_roots)
        )):
            raise Failure("denied", "This credential does not permit the action.", 403)

    def public(self) -> dict:
        return {"id": self.id, "label": self.label, "scopes": self.scopes,
                "node_ids": self.effective("nodes"), "root_ids": self.effective("roots"),
                "subject_id": self.subject_id, "project_id": self.project_id, "local_owner": self.local_owner}


class Auth:
    def __init__(self, store: Store):
        self.store = store
        self.identities = Identities(store)
        self.resources = Resources(store)
        self.on_revoke: Callable[[str, list[str] | None], None] | None = None
        self.policy_check: Callable | None = None
        self.external_check: Callable | None = None
        self.external_rotate: Callable | None = None
        self.external_revoke: Callable | None = None

    def issue(self, kind: str, label: str = "Local owner", scopes: list[str] | None = None,
              node_ids: list[str] | None = None, lifetime: int = 3600,
              root_ids: list[str] | None = None, *, subject_id: str = LOCAL_OWNER,
              project_id: str = LOCAL_PROJECT) -> tuple[str, Principal]:
        permitted = self.identities.access(subject_id, project_id)
        if label == "Local owner" and subject_id != LOCAL_OWNER:
            label = self.identities.user(subject_id)["label"]
        scopes = sorted(permitted if scopes is None else set(scopes))
        if kind not in {"bootstrap", "session", "token", "remote"} or set(scopes) - permitted:
            raise Failure("denied", "The credential exceeds the identity's project access.", 403)
        if kind == "remote" and subject_id == LOCAL_OWNER:
            raise Failure("denied", "External identities cannot use the local recovery owner.", 403)
        if not scopes or not set(scopes).issubset(SCOPES):
            raise Failure("invalid_scope", "Select supported permission scopes.")
        if not 1 <= lifetime <= 2592000 or not 1 <= len(label) <= 80:
            raise Failure("invalid_credential", "Credential label or lifetime is invalid.")
        if node_ids is not None:
            if len(node_ids) > MAX_NODES or any(not isinstance(n, str) for n in node_ids):
                raise Failure("invalid_nodes", "The machine selection is invalid.")
            for node_id in node_ids:
                self.store.endpoint_kind(node_id)
        if root_ids is not None:
            if len(root_ids) > 64 or any(not isinstance(r, str) for r in root_ids):
                raise Failure("invalid_roots", "The folder selection is invalid.")
            with self.store.lock:
                for root_id in root_ids:
                    if self.store.db.execute("SELECT id FROM file_roots WHERE id=:p0", (root_id,)).fetchone() is None:
                        raise Failure("invalid_roots", "The registered folder was not found.")
        value = secrets.token_urlsafe(32)
        principal = Principal(secrets.token_hex(16), label, scopes, node_ids,
                              secrets.token_urlsafe(24), kind, time.time() + lifetime, root_ids, subject_id, project_id)
        with self.store.lock, self.store.db:
            if set(scopes) - self.identities.access(subject_id, project_id):
                raise Failure("denied", "Project access changed before credential creation.", 403)
            self.store.db.execute("DELETE FROM credentials WHERE expires < :p0", (time.time(),))
            count = self.store.db.execute("SELECT count(*) FROM credentials").fetchone()[0]
            if count >= 512:
                raise Failure("capacity", "The credential limit was reached.", 409)
            self.store.db.execute("INSERT INTO credentials VALUES (:p0,:p1,:p2,:p3,:p4,:p5,:p6,:p7,:p8,:p9,:p10)", (
                principal.id, digest(value), kind, label, json.dumps(scopes),
                json.dumps(node_ids), principal.expires_at, principal.csrf, json.dumps(root_ids), subject_id, project_id))
        return value, self._resources(principal)

    def resolve(self, value: str, kinds: tuple[str, ...] = ("session", "token"),
                consume: bool = False) -> Principal:
        if not value or len(value) > 128:
            raise Failure("unauthenticated", "Sign in to continue.", 401)
        with self.store.lock, self.store.db:
            row = self._access_row("digest", digest(value))
            accepted = (*kinds, "remote") if "session" in kinds else kinds
            if row is None or row[5] not in accepted or row[6] <= time.time():
                raise Failure("unauthenticated", "Sign in to continue.", 401)
            principal = self._principal(row)
            if consume:
                self.store.db.execute("DELETE FROM credentials WHERE id=:p0", (row[0],))
            return principal

    def revoke(self, credential_id: str, actor: str = "local-owner") -> None:
        with self.store.lock, self.store.db:
            row = self.store.db.execute("SELECT subject_id,project_id FROM credentials WHERE id=:p0", (actor,)).fetchone()
            revoked = self.store.db.execute("SELECT subject_id,nodes FROM credentials WHERE id=:p0", (credential_id,)).fetchone()
            self.store.db.execute("DELETE FROM credentials WHERE id=:p0", (credential_id,))
        if revoked and self.on_revoke:
            self.on_revoke(revoked[0], json.loads(revoked[1]))
        if self.external_revoke:
            self.external_revoke(credential_id)
        self.store.audit("credential.revoke", credential_id, actor=actor,
                         subject_id=row[0] if row else None, project_id=row[1] if row else None)

    def current(self, credential_id: str) -> Principal:
        """Read current grants again before a queued operation is dispatched."""
        with self.store.lock:
            row = self._access_row("id", credential_id)
            if row is None or row[5] not in ("session", "token", "remote") or row[6] <= time.time():
                raise Failure("unauthenticated", "Sign in to continue.", 401)
            return self._principal(row)

    def _access_row(self, column: str, value: str):
        if column not in {"digest", "id"}:
            raise ValueError("The credential lookup field is invalid.")
        # One database snapshot keeps current identity, membership and assignments consistent.
        return self.store.db.execute(
            "SELECT c.id,c.label,c.scopes,c.nodes,c.csrf,c.kind,c.expires,c.roots,c.subject_id,c.project_id,"
            "u.disabled,p.disabled,m.scopes,r.nodes,r.roots FROM credentials c "
            "JOIN identities u ON u.id=c.subject_id JOIN projects p ON p.id=c.project_id "
            "LEFT JOIN project_memberships m ON m.subject_id=c.subject_id AND m.project_id=c.project_id "
            "LEFT JOIN project_resources r ON r.project_id=c.project_id "
            f"WHERE c.{column}=:p0", (value,)).fetchone()

    def _principal(self, row) -> Principal:
        if row[5] == "remote":
            if self.external_check is None:
                raise Failure("unauthenticated", "External sign-in is unavailable.", 401)
            self.external_check(row[0], row[8])
        if row[10] or row[11]:
            raise Failure("unauthenticated", "The identity or project is disabled.", 401)
        permitted = set(SCOPES)
        if row[8] != LOCAL_OWNER:
            if row[12] is None or not json.loads(row[12]):
                raise Failure("unauthenticated", "Project membership is required.", 401)
            permitted = set(json.loads(row[12])) & PROJECT_SCOPES
        return Principal(row[0], row[1], sorted(set(json.loads(row[2])) & permitted), json.loads(row[3]),
                         row[4], row[5], row[6], json.loads(row[7]), row[8], row[9],
                         json.loads(row[13]) if row[13] is not None else [],
                         json.loads(row[14]) if row[14] is not None else [], self.policy_check)

    def _resources(self, principal: Principal) -> Principal:
        principal.policy_check = self.policy_check
        if not principal.local_owner:
            resources = self.resources.get(principal.project_id)
            principal.project_nodes = resources["node_ids"]
            principal.project_roots = resources["root_ids"]
        return principal

    def ownership(self, actor: str) -> dict:
        principal = self.current(actor)
        return {"subject_id": principal.subject_id, "project_id": principal.project_id}

    def record(self, actor: str, value: dict, *, private: bool = False) -> Principal:
        principal = self.current(actor)
        principal.require_record(value, private=private)
        return principal

    def switch_project(self, credential_id: str, project_id: str) -> tuple[str, Principal]:
        """Rotate within current project access and preserve delegated local scope ceilings."""
        with self.store.lock, self.store.db:
            current = self.current(credential_id)
            if current.kind not in {"session", "remote"}:
                raise Failure("denied", "Only a browser session can change its selected project.", 403)
            try:
                self.identities.access(current.subject_id, project_id)
            except Failure:
                raise Failure("denied", "The selected project is unavailable to this identity.", 403) from None
            row = self.store.db.execute("SELECT scopes,nodes,roots FROM credentials WHERE id=:p0", (credential_id,)).fetchone()
            scopes = row[0]
            if current.kind == "remote":
                # The external session binds an approved identity, not a delegated bearer grant.
                scopes = json.dumps(sorted(self.identities.access(current.subject_id, project_id)))
            secret, identity, csrf = secrets.token_urlsafe(32), secrets.token_hex(16), secrets.token_urlsafe(24)
            self.store.db.execute("INSERT INTO credentials VALUES (:p0,:p1,:p2,:p3,:p4,:p5,:p6,:p7,:p8,:p9,:p10)", (
                identity, digest(secret), current.kind, current.label, scopes, row[1], current.expires_at,
                csrf, row[2], current.subject_id, project_id))
            self.store.db.execute("DELETE FROM credentials WHERE id=:p0", (credential_id,))
            if current.kind == "remote" and self.external_rotate:
                self.external_rotate(credential_id, identity)
            value = self.current(identity)
        if self.on_revoke:
            self.on_revoke(current.subject_id, current.node_ids)
        return secret, value

    def tokens(self) -> list[dict]:
        with self.store.lock:
            rows = self.store.db.execute(
                "SELECT id,label,scopes,nodes,expires,roots,subject_id,project_id FROM credentials "
                "WHERE kind='token' AND expires > :p0 ORDER BY label", (time.time(),)).fetchall()
        return [{"id": r[0], "label": r[1], "scopes": json.loads(r[2]),
                 "node_ids": json.loads(r[3]), "expires_at": r[4], "root_ids": json.loads(r[5]),
                 "subject_id": r[6], "project_id": r[7]} for r in rows]
