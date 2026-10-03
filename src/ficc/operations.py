# SPDX-License-Identifier: Apache-2.0
"""Report observed service health and export an explicit diagnostic allowlist."""

import hashlib
import json
import math
import os
import re
import secrets
import time
from pathlib import Path

from cryptography import x509

from . import __version__
from .errors import Failure
from .state_provider import read_private

RECEIPTS = {"backup": "operations-backup.json", "restore": "operations-restore.json"}


def receipt(state, kind):
    path = Path(state) / RECEIPTS[kind]
    try:
        value = json.loads(read_private(path, 4096))
        if (set(value) != {"kind", "at", "manifest_sha256", "schema", "members"}
                or value["kind"] != kind or type(value["at"]) not in {int, float}
                or not math.isfinite(value["at"]) or value["at"] < 0
                or not isinstance(value["manifest_sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", value["manifest_sha256"])
                or type(value["schema"]) is not int or type(value["members"]) is not int):
            raise ValueError("Invalid operation receipt")
        return {"state": "recorded", **value, "age_seconds": max(0, time.time() - value["at"])}
    except FileNotFoundError:
        return {"state": "not_recorded"}
    except (OSError, ValueError, TypeError):
        return {"state": "unavailable"}


def save_receipt(state, kind, manifest, raw, *, directory_fd=None):
    from .backup_io import checked, directory

    value = {"kind": kind, "at": time.time(), "manifest_sha256": hashlib.sha256(raw).hexdigest(),
             "schema": manifest["schema"], "members": len(manifest["members"])}
    if directory_fd is None:
        with directory(Path(state)) as folder:
            return save_receipt(state, kind, manifest, raw, directory_fd=folder)
    checked(os.fstat(directory_fd), directory=True)
    name = ".operations-receipt-" + secrets.token_hex(16)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, RECEIPTS[kind], src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


class Operations:
    def __init__(self, service):
        self.service = service

    def authorize(self, actor):
        value = self.service.auth.current(actor)
        value.require("audit:read")
        if not value.local_owner or value.node_ids is not None or value.root_ids is not None:
            raise Failure("denied", "Installation-wide operational reports require unrestricted owner access.", 403)
        return value

    def health(self, actor):
        self.authorize(actor)
        service = self.service
        now = time.time()
        nodes = service.store.nodes()
        connections = {"ready": 0, "stale": 0, "unreachable": 0}
        for node in nodes:
            view = service.view(node)
            key = "unreachable" if view["state"] == "unreachable" else "stale" if view["stale"] else "ready"
            connections[key] += 1
        certificates = []
        if service.settings.contributors:
            for certificate in x509.load_pem_x509_certificates(service.settings.contributors.ca):
                expires = certificate.not_valid_after_utc.timestamp()
                starts = certificate.not_valid_before_utc.timestamp()
                certificates.append({"kind": "contributor_authority", "expires_at": expires,
                    "valid_from": starts, "remaining_seconds": expires - now,
                    "state": "valid" if starts <= now < expires else "invalid"})
        policy = service.policies.records.state()
        backup = receipt(service.settings.state_dir, "backup")
        restore = receipt(service.settings.state_dir, "restore")
        from .secret_sdk import SecretError
        from .secrets import CONFIG, PRIVATE, Secrets
        secret_state = "not_configured"
        if (service.settings.state_dir / PRIVATE / CONFIG).exists():
            try:
                Secrets(service.settings.state_dir).status()
                secret_state = "available"
            except SecretError:
                secret_state = "unavailable"
        return {"observed_at": now, "version": __version__, "mode": "remote" if service.settings.remote else "local",
            "connections": connections, "certificates": certificates,
            "gateway_certificate": "external_not_observed" if service.settings.remote else "not_applicable",
            "policy": {"required": bool(policy.get("required")), "revision": policy["revision"],
                       "state": "unavailable" if service.policies.error else "active" if service.policies.prepared else "not_configured"},
            "backup": backup, "restore": restore,
            "secret_store": secret_state,
            "audit_delivery": service.audit_delivery.status(),
            "external_data_backup": "not_observed", "storage_encryption": "externally_managed_not_verified",
            "background_errors": {"resources": service.poll_error, "jobs": service.jobs.failed,
                                  "agents": service.agents.poll_error, "workloads": service.workloads.runner.failed},
            "audit": self.audit_bounds()}

    def audit_bounds(self):
        with self.service.store.lock:
            first, last, count = self.service.store.db.execute("SELECT min(id),max(id),count(*) FROM audit").fetchone()
        return {"first_id": first, "last_id": last, "retained_events": count,
                "earlier_events_removed": first is not None and first > 1}

    def diagnostics(self, actor):
        # Never include queries, payloads, labels, routes, paths, credentials or raw exceptions.
        result = self.health(actor)
        result["format"] = "ficc-diagnostics-v1"
        result["scope"] = "Allowlisted installation status; no event contents or source configuration."
        return result

    def audit_page(self, actor, after, through):
        self.authorize(actor)
        with self.service.store.lock:
            rows = self.service.store.db.execute(
                "SELECT id,at,action,target,outcome,actor,subject_id,project_id FROM audit "
                "WHERE id>:p0 AND id<=:p1 ORDER BY id LIMIT 200", (after, through)).fetchall()
        fields = ("id", "at", "action", "target", "outcome", "actor", "subject_id", "project_id")
        return [dict(zip(fields, row, strict=True)) for row in rows]

    async def export_audit(self, actor, after, through):
        import asyncio
        bounds = self.audit_bounds()
        gap = bounds["first_id"] is not None and after < bounds["first_id"] - 1
        yield json.dumps({"format": "ficc-audit-v1", "after": after, "through": through,
                          "retention_gap": gap, **bounds}) + "\n"
        while after < through:
            values = await asyncio.to_thread(self.audit_page, actor, after, through)
            if not values:
                break
            for value in values:
                if value["id"] > after + 1:
                    gap = True
                    yield json.dumps({"retention_gap": True, "after": after, "before": value["id"]}) + "\n"
                yield json.dumps(value, separators=(",", ":")) + "\n"
                after = value["id"]
            await asyncio.sleep(0)
        self.authorize(actor)
        yield json.dumps({"complete": after >= through, "retention_gap": gap, "last_id": after, "through": through}) + "\n"
