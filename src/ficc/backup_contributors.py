# SPDX-License-Identifier: Apache-2.0
"""Validate contributor metadata and remove restored authority."""

import json
import math

from .contributor_settings import FINGERPRINT, IDENTITY


def identity(value):
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise ValueError("A contributor identifier is invalid.")


def finite(value):
    if type(value) not in {int, float} or not math.isfinite(value) or value <= 0:
        raise ValueError("A contributor timestamp is invalid.")


def revision(value):
    if type(value) is not int or not 1 <= value <= 2**53 - 1:
        raise ValueError("A contributor revision is invalid.")


def fingerprint(value):
    if not isinstance(value, str) or not FINGERPRINT.fullmatch(value):
        raise ValueError("A contributor fingerprint is invalid.")


def validate_records(db):
    projects = {row[0] for row in db.execute("SELECT id FROM projects")}
    nodes = {}
    for key, project, raw in db.execute("SELECT * FROM contributors"):
        value = json.loads(raw)
        if set(value) != {"id", "project_id", "name", "mode", "disabled", "revision", "created_at"}:
            raise ValueError("A contributor record is invalid.")
        identity(key)
        revision(value["revision"])
        finite(value["created_at"])
        if (value["id"] != key or value["project_id"] != project or project not in projects
                or value["mode"] not in {"managed", "voluntary"} or type(value["disabled"]) is not bool
                or not isinstance(value["name"], str) or not value["name"].strip() or len(value["name"]) > 80):
            raise ValueError("A contributor identity or project is invalid.")
        nodes[key] = value
    for key, secret, project, raw in db.execute("SELECT * FROM contributor_invitations"):
        value = json.loads(raw)
        if set(value) != {"id", "node_id", "project_id", "name", "mode", "expires_at", "used"}:
            raise ValueError("A contributor invitation record is invalid.")
        identity(key)
        identity(value["node_id"])
        fingerprint(secret)
        finite(value["expires_at"])
        if (value["id"] != key or value["project_id"] != project or project not in projects
                or value["mode"] not in {"managed", "voluntary"} or type(value["used"]) is not bool
                or not isinstance(value["name"], str) or not value["name"].strip() or len(value["name"]) > 80):
            raise ValueError("A contributor invitation is invalid.")
    for key, node_id, receipt, raw in db.execute("SELECT * FROM contributor_requests"):
        value = json.loads(raw)
        if set(value) != {"id", "node_id", "csr_pem", "public_key", "kind", "base_fingerprint", "status", "expires_at", "revision", "certificate_fingerprint"}:
            raise ValueError("A contributor request record is invalid.")
        identity(key)
        fingerprint(value["public_key"])
        finite(value["expires_at"])
        revision(value["revision"])
        if (value["id"] != key or value["node_id"] != node_id or node_id not in nodes
                or value["kind"] not in {"enroll", "rotate"}
                or value["status"] not in {"awaiting_approval", "issuing", "failed", "issued"}
                or not isinstance(value["csr_pem"], str) or not 100 <= len(value["csr_pem"]) <= 8192):
            raise ValueError("A contributor request is invalid.")
        if value["kind"] == "enroll":
            fingerprint(receipt)
            if value["base_fingerprint"] is not None:
                raise ValueError("An enrollment request has a rotation identity.")
        else:
            fingerprint(value["base_fingerprint"])
            if receipt != "":
                raise ValueError("A rotation request has an enrollment receipt.")
        if value["certificate_fingerprint"] is not None:
            fingerprint(value["certificate_fingerprint"])
    active = set()
    for key, node_id, raw in db.execute("SELECT * FROM contributor_certificates"):
        value = json.loads(raw)
        if set(value) != {"fingerprint", "public_key", "not_before", "expires_at", "certificate_chain", "node_id", "request_id", "status"}:
            raise ValueError("A contributor certificate record is invalid.")
        fingerprint(key)
        fingerprint(value["public_key"])
        identity(value["request_id"])
        finite(value["not_before"])
        finite(value["expires_at"])
        if (value["fingerprint"] != key or value["node_id"] != node_id or node_id not in nodes
                or value["status"] not in {"pending", "current", "revoked"}
                or not value["not_before"] < value["expires_at"]
                or not isinstance(value["certificate_chain"], str) or len(value["certificate_chain"]) > 16384
                or value["status"] == "current" and (node_id in active or nodes[node_id]["disabled"])):
            raise ValueError("A contributor certificate is invalid.")
        if value["status"] == "current":
            active.add(node_id)


def suspend(db):
    for table in ("contributor_invitations", "contributor_requests", "contributor_certificates"):
        db.execute(f"DELETE FROM {table}")
    for key, raw in db.execute("SELECT id,value FROM contributors").fetchall():
        value = json.loads(raw)
        value.update(disabled=True, revision=value["revision"] + 1)
        db.execute("UPDATE contributors SET value=:p0 WHERE id=:p1", (json.dumps(value), key))
