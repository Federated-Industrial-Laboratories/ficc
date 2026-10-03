# SPDX-License-Identifier: Apache-2.0
"""Persist atomic contributor invitations, approval and certificate transitions."""

import hashlib
import json
import secrets
import time

from .errors import Failure
from .identity_store import Identities

TABLES = {"contributors", "contributor_invitations", "contributor_requests", "contributor_certificates"}


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS contributors (id TEXT PRIMARY KEY, "
               "project_id TEXT NOT NULL REFERENCES projects(id), value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS contributor_invitations (id TEXT PRIMARY KEY, "
               "digest TEXT UNIQUE NOT NULL, project_id TEXT NOT NULL REFERENCES projects(id), value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS contributor_requests (id TEXT PRIMARY KEY, "
               "node_id TEXT NOT NULL REFERENCES contributors(id), receipt_digest TEXT NOT NULL, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS contributor_certificates (fingerprint TEXT PRIMARY KEY, "
               "node_id TEXT NOT NULL REFERENCES contributors(id), value TEXT NOT NULL)")


def digest(secret):
    if not isinstance(secret, str) or not 43 <= len(secret) <= 128 or not secret.isascii():
        raise Failure("invalid_invitation", "The invitation or receipt is invalid.", 403)
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


class Records:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings

    def rows(self, table):
        assert table in TABLES
        with self.store.lock:
            return [json.loads(row[0]) for row in self.store.db.execute(f"SELECT value FROM {table}")]

    def get(self, table, identity):
        assert table in TABLES
        column = "fingerprint" if table == "contributor_certificates" else "id"
        with self.store.lock:
            row = self.store.db.execute(f"SELECT value FROM {table} WHERE {column}=:p0", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The contributor record was not found.", 404)
        return json.loads(row[0])

    def update(self, table, value):
        assert table in TABLES
        column = "fingerprint" if table == "contributor_certificates" else "id"
        self.store.db.execute(f"UPDATE {table} SET value=:p0 WHERE {column}=:p1",
                              (json.dumps(value, allow_nan=False), value[column]))

    def audit(self, action, identity, actor=None, outcome="success"):
        self.store.audit(action, identity, outcome, actor.id if actor else "node:" + identity,
                         subject_id=actor.subject_id if actor else None,
                         project_id=actor.project_id if actor else None)

    def project(self, project_id):
        if Identities(self.store).project(project_id)["disabled"]:
            raise Failure("project_disabled", "This contributor project is disabled.", 403)

    def prune(self):
        now = time.time()
        for row in self.rows("contributor_invitations"):
            if row["expires_at"] <= now:
                self.store.db.execute("DELETE FROM contributor_invitations WHERE id=:p0", (row["id"],))
        for row in self.rows("contributor_certificates"):
            if row["expires_at"] <= now:
                self.store.db.execute("DELETE FROM contributor_certificates WHERE fingerprint=:p0", (row["fingerprint"],))
        for row in self.rows("contributor_requests"):
            if row["expires_at"] <= now:
                self.store.db.execute("DELETE FROM contributor_requests WHERE id=:p0", (row["id"],))

    def invite(self, name, mode, actor):
        with self.store.lock, self.store.db:
            self.project(actor.project_id)
            self.prune()
            if len(self.rows("contributor_invitations")) >= 128:
                raise Failure("capacity", "The pending invitation limit was reached.", 409)
            secret = secrets.token_urlsafe(32)
            value = {"id": secrets.token_hex(16), "node_id": secrets.token_hex(16),
                     "project_id": actor.project_id, "name": name, "mode": mode,
                     "expires_at": time.time() + self.settings.invitation_seconds, "used": False}
            self.store.db.execute("INSERT INTO contributor_invitations VALUES (:p0,:p1,:p2,:p3)",
                                  (value["id"], digest(secret), actor.project_id, json.dumps(value)))
            self.audit("contributor.invite", value["id"], actor)
            return {**value, "secret": secret}

    def claim(self, secret, csr, node_id):
        from .contributor_certificates import request
        token_digest = digest(secret)
        with self.store.lock, self.store.db:
            self.prune()
            if len(self.rows("contributor_requests")) >= 512:
                raise Failure("capacity", "Wait for retained enrollment requests to expire.", 409)
            row = self.store.db.execute("SELECT value FROM contributor_invitations WHERE digest=:p0", (token_digest,)).fetchone()
            value = json.loads(row[0]) if row else None
            if not value or value["used"] or value["expires_at"] <= time.time() or value["node_id"] != node_id:
                raise Failure("invalid_invitation", "The invitation expired or was already used.", 403)
            self.project(value["project_id"])
            if len(self.rows("contributors")) >= self.settings.max_nodes:
                raise Failure("capacity", "The contributor limit was reached.", 409)
            public_key = request(csr, self.settings.uri(node_id), node_id)
            node = {"id": node_id, "project_id": value["project_id"], "name": value["name"],
                    "mode": value["mode"], "disabled": False, "revision": 1, "created_at": time.time()}
            self.store.db.execute("INSERT INTO contributors VALUES (:p0,:p1,:p2)",
                                  (node_id, node["project_id"], json.dumps(node)))
            receipt = secrets.token_urlsafe(32)
            pending = {"id": secrets.token_hex(16), "node_id": node_id, "csr_pem": csr,
                       "public_key": public_key, "kind": "enroll", "base_fingerprint": None,
                       "status": "awaiting_approval", "expires_at": value["expires_at"],
                       "revision": 1, "certificate_fingerprint": None}
            self.store.db.execute("INSERT INTO contributor_requests VALUES (:p0,:p1,:p2,:p3)",
                                  (pending["id"], node_id, digest(receipt), json.dumps(pending)))
            value["used"] = True
            self.update("contributor_invitations", value)
            self.audit("contributor.request", node_id)
            return pending, receipt

    def receipt(self, identity, secret):
        token_digest = digest(secret)
        with self.store.lock:
            row = self.store.db.execute("SELECT value,receipt_digest FROM contributor_requests WHERE id=:p0", (identity,)).fetchone()
            if not row or not secrets.compare_digest(row[1], token_digest):
                raise Failure("invalid_receipt", "The enrollment receipt is invalid.", 403)
            pending = json.loads(row[0])
            node = self.get("contributors", pending["node_id"])
            self.project(node["project_id"])
            if node["disabled"] or pending["expires_at"] <= time.time():
                raise Failure("enrollment_expired", "The enrollment request is disabled or expired.", 403)
            result = {"request_id": identity, "node_id": node["id"], "status": pending["status"]}
            if pending["status"] == "issued":
                cert = self.get("contributor_certificates", pending["certificate_fingerprint"])
                if cert["status"] == "revoked" or cert["expires_at"] <= time.time():
                    raise Failure("certificate_revoked", "This certificate is no longer accepted.", 403)
                result.update({"certificate_chain": cert["certificate_chain"], "expires_at": cert["expires_at"]})
            return result

    def begin_issue(self, identity, expected, revision, actor=None):
        with self.store.lock, self.store.db:
            pending = self.get("contributor_requests", identity)
            node = self.get("contributors", pending["node_id"])
            self.project(node["project_id"])
            if actor and node["project_id"] != actor.project_id:
                raise Failure("not_found", "The contributor request was not found.", 404)
            if (node["disabled"] or pending["expires_at"] <= time.time()
                    or pending["revision"] != revision or pending["public_key"] != expected
                    or pending["status"] not in {"awaiting_approval", "failed", "issuing"}):
                raise Failure("request_changed", "Reload the current request and confirm its public key.", 409)
            if pending["kind"] == "rotate":
                self.authenticate(pending["base_fingerprint"])
            pending.update(status="issuing", revision=pending["revision"] + 1)
            self.update("contributor_requests", pending)
            self.audit("contributor.approve", pending["node_id"], actor)
            return pending

    def issued(self, pending, cert):
        with self.store.lock, self.store.db:
            current = self.get("contributor_requests", pending["id"])
            node = self.get("contributors", pending["node_id"])
            self.project(node["project_id"])
            if current != pending or node["disabled"] or pending["expires_at"] <= time.time():
                raise Failure("request_changed", "The contributor request no longer permits issuance.", 409)
            if pending["kind"] == "rotate":
                self.authenticate(pending["base_fingerprint"])
            self.prune()
            if len(self.rows("contributor_certificates")) >= 256:
                raise Failure("capacity", "Wait for retained certificates to expire.", 409)
            cert.update(node_id=node["id"], request_id=pending["id"], status="pending")
            self.store.db.execute("INSERT INTO contributor_certificates VALUES (:p0,:p1,:p2)",
                                  (cert["fingerprint"], node["id"], json.dumps(cert)))
            current.update(status="issued", certificate_fingerprint=cert["fingerprint"], revision=current["revision"] + 1)
            self.update("contributor_requests", current)
            self.audit("contributor.certificate", node["id"])
            return current

    def failed(self, pending):
        with self.store.lock, self.store.db:
            try:
                current = self.get("contributor_requests", pending["id"])
            except Failure:
                return
            if current == pending:
                current.update(status="failed", revision=current["revision"] + 1)
                self.update("contributor_requests", current)
                self.audit("contributor.certificate", pending["node_id"], outcome="failed")

    def authenticate(self, fingerprint, *, pending=False):
        with self.store.lock:
            row = self.store.db.execute(
                "SELECT c.value,n.value,p.disabled FROM contributor_certificates c "
                "JOIN contributors n ON n.id=c.node_id JOIN projects p ON p.id=n.project_id "
                "WHERE c.fingerprint=:p0", (fingerprint,)).fetchone()
        if row is None:
            raise Failure("not_found", "The contributor certificate was not found.", 404)
        cert, node = json.loads(row[0]), json.loads(row[1])
        if row[2]:
            raise Failure("project_disabled", "This contributor project is disabled.", 403)
        if (node["disabled"] or cert["status"] not in ({"pending", "current"} if pending else {"current"})
                or not cert["not_before"] <= time.time() < cert["expires_at"]):
            raise Failure("node_unauthorized", "The contributor certificate is not currently authorized.", 403)
        return node, cert

    def active_certificates(self, fingerprints):
        if not fingerprints:
            return set()
        assert len(fingerprints) <= 64
        parameters = ",".join(f":p{index}" for index in range(len(fingerprints)))
        with self.store.lock:
            rows = list(self.store.db.execute(
                "SELECT c.fingerprint,c.value,n.value,p.disabled FROM contributor_certificates c "
                "JOIN contributors n ON n.id=c.node_id JOIN projects p ON p.id=n.project_id "
                f"WHERE c.fingerprint IN ({parameters})", tuple(fingerprints)))
        now = time.time()
        active = set()
        for fingerprint, certificate, contributor, disabled in rows:
            cert, node = json.loads(certificate), json.loads(contributor)
            if (not disabled and not node["disabled"] and cert["status"] == "current"
                    and cert["not_before"] <= now < cert["expires_at"]):
                active.add((node["id"], fingerprint))
        return active

    def activate(self, fingerprint):
        with self.store.lock, self.store.db:
            node, cert = self.authenticate(fingerprint, pending=True)
            if cert["status"] == "current":
                return node, []
            request = self.get("contributor_requests", cert["request_id"])
            if request["expires_at"] <= time.time() or request["status"] != "issued":
                raise Failure("enrollment_expired", "The certificate activation window expired.", 403)
            if request["kind"] == "rotate":
                self.authenticate(request["base_fingerprint"])
            previous = []
            for item in self.rows("contributor_certificates"):
                if item["node_id"] == node["id"] and item["status"] != "revoked" and item["fingerprint"] != fingerprint:
                    item["status"] = "revoked"
                    self.update("contributor_certificates", item)
                    previous.append(item)
            cert["status"] = "current"
            self.update("contributor_certificates", cert)
            node["revision"] += 1
            self.update("contributors", node)
            self.audit("contributor.activate", node["id"])
            return node, previous

    def rotation(self, fingerprint, identity, csr):
        from .contributor_certificates import request
        with self.store.lock, self.store.db:
            node, current = self.authenticate(fingerprint)
            public_key = request(csr, self.settings.uri(node["id"]), node["id"])
            if public_key == current["public_key"]:
                raise Failure("key_rotation_required", "Generate a new node key before rotation.", 409)
            self.prune()
            if len(self.rows("contributor_requests")) >= 512:
                raise Failure("capacity", "Wait for retained rotation requests to expire.", 409)
            for previous in self.rows("contributor_requests"):
                if previous["id"] == identity:
                    if (previous["node_id"], previous["csr_pem"], previous["base_fingerprint"]) != (node["id"], csr, fingerprint):
                        raise Failure("request_conflict", "The rotation request identifier was already used.", 409)
                    return previous
                if previous["node_id"] == node["id"] and previous["kind"] == "rotate" and previous["status"] != "failed":
                    cert_id = previous["certificate_fingerprint"]
                    if cert_id is None or self.get("contributor_certificates", cert_id)["status"] == "pending":
                        raise Failure("rotation_pending", "Complete or let the pending rotation expire.", 409)
            value = {"id": identity, "node_id": node["id"], "csr_pem": csr,
                     "public_key": public_key, "kind": "rotate", "base_fingerprint": fingerprint,
                     "status": "awaiting_approval", "expires_at": min(current["expires_at"], time.time() + self.settings.invitation_seconds),
                     "revision": 1, "certificate_fingerprint": None}
            self.store.db.execute("INSERT INTO contributor_requests VALUES (:p0,:p1,:p2,:p3)",
                                  (identity, node["id"], "", json.dumps(value)))
            return value

    def disable(self, identity, revision, actor):
        with self.store.lock, self.store.db:
            node = self.get("contributors", identity)
            if node["project_id"] != actor.project_id:
                raise Failure("not_found", "The contributor was not found.", 404)
            if node["revision"] != revision:
                raise Failure("revision_conflict", "The contributor changed. Reload it before revocation.", 409)
            node.update(disabled=True, revision=revision + 1)
            self.update("contributors", node)
            revoked = []
            for cert in self.rows("contributor_certificates"):
                if cert["node_id"] == identity and cert["status"] != "revoked":
                    cert["status"] = "revoked"
                    self.update("contributor_certificates", cert)
                    revoked.append(cert)
            self.audit("contributor.disable", identity, actor)
            return node, revoked

    def remove(self, identity, revision, actor):
        with self.store.lock, self.store.db:
            node = self.get("contributors", identity)
            if node["project_id"] != actor.project_id:
                raise Failure("not_found", "The contributor was not found.", 404)
            if node["revision"] != revision or not node["disabled"]:
                raise Failure("revision_conflict", "Revoke the contributor and reload it before removal.", 409)
            from .workloads.authority import retained_for_node
            if retained_for_node(self.store, identity):
                raise Failure("workload_retained", "Resolve and remove retained workloads before removing this contributor.", 409)
            for table in ("contributor_requests", "contributor_certificates"):
                self.store.db.execute(f"DELETE FROM {table} WHERE node_id=:p0", (identity,))
            for invite in self.rows("contributor_invitations"):
                if invite["node_id"] == identity:
                    self.store.db.execute("DELETE FROM contributor_invitations WHERE id=:p0", (invite["id"],))
            self.store.db.execute("DELETE FROM workload_nodes WHERE node_id=:p0", (identity,))
            self.store.db.execute("DELETE FROM contributors WHERE id=:p0", (identity,))
            self.audit("contributor.remove", identity, actor)
            return {"id": identity, "removed": True}
