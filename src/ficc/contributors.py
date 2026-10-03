# SPDX-License-Identifier: Apache-2.0
"""Own approved contributor certificates and bounded live authority leases."""

import asyncio
import secrets
import time

from . import contributor_certificates
from .contributor_store import Records
from .errors import Failure
from .modules.sandbox import finish_cleanup


class Contributors:
    def __init__(self, service):
        self.service = service
        self.settings = service.settings.contributors
        self.records = Records(service.store, self.settings)
        self.provider = None
        self.slots = asyncio.Semaphore(4)
        self.issuing: set[str] = set()
        self.sessions: dict[str, dict] = {}
        self.provider_error = False
        if self.settings:
            previous = service.store.get_setting("contributors.deployment_id", self.settings.deployment_id)
            if previous != self.settings.deployment_id:
                raise ValueError("The contributor authority belongs to another installation.")
            service.store.set_setting("contributors.deployment_id", previous)

    async def start(self):
        if self.settings is not None and self.provider is None:
            try:
                self.provider = await asyncio.to_thread(contributor_certificates.create, self.settings.issuer)
                self.provider_error = False
            except Exception:
                self.provider_error = True

    async def poll(self):
        if self.settings is None:
            return
        while True:
            await asyncio.sleep(1)
            if not self.sessions:
                continue
            try:
                active = self.records.active_certificates({value["fingerprint"] for value in self.sessions.values()})
            except Exception:
                self.sessions.clear()
                continue
            now = time.monotonic()
            for identity, session in list(self.sessions.items()):
                if (identity, session["fingerprint"]) not in active or session["deadline"] <= now:
                    self.sessions.pop(identity, None)
                else:
                    session["verified_at"] = now

    def close(self):
        self.sessions.clear()
        if self.provider is not None:
            try:
                self.provider.close()
            finally:
                self.provider = None

    def configured(self):
        if self.settings is None:
            raise Failure("contributors_unavailable", "Configure a contributor gateway and certificate authority first.", 409)

    def permission(self, actor, scope):
        value = self.service.auth.current(actor.id)
        value.require(scope)
        if value.project_id != actor.project_id or value.node_ids is not None or value.root_ids is not None:
            raise Failure("denied", "This action requires an unrestricted credential within its project.", 403)
        return value

    def status(self):
        return {"configured": self.settings is not None, "issuer_ready": self.provider is not None,
                "origin": self.settings.origin if self.settings else None,
                "lease_seconds": self.settings.lease_seconds if self.settings else None,
                "execution_available": bool(getattr(self.service, "workloads", None) and self.service.workloads.scheduler)}

    def all(self, actor):
        self.permission(actor, "contributors:read")
        values = []
        requests = self.records.rows("contributor_requests")
        stored_certificates = self.records.rows("contributor_certificates")
        for node in self.records.rows("contributors"):
            if node["project_id"] != actor.project_id:
                continue
            session = self.sessions.get(node["id"])
            live = False
            if session:
                try:
                    self.guard(node["id"], session["id"], session["fingerprint"])
                    live = True
                except Failure:
                    pass
            pending = [{key: value[key] for key in ("id", "kind", "public_key", "status", "expires_at", "revision")}
                       for value in requests
                       if value["node_id"] == node["id"] and value["expires_at"] > time.time()]
            certificates = [{key: value[key] for key in ("fingerprint", "public_key", "expires_at", "status")}
                            for value in stored_certificates if value["node_id"] == node["id"]]
            values.append({**node, "connected": live, "connection": session["transport"] if live and session else None,
                           "sample": session["sample"] if live and session else None,
                           "last_seen": session["seen"] if session else None,
                           "execution_available": self.service.workloads.runner.available(node["id"]),
                           "requests": pending, "certificates": certificates})
        return {"contributors": values, **self.status()}

    def invite(self, name, mode, actor):
        self.configured()
        self.permission(actor, "contributors:manage")
        self.service.live()
        value = self.records.invite(name, mode, actor)
        return {"format": "ficc-node-invitation", "version": 1,
                "controller": self.service.settings.origin, "node_origin": self.settings.origin,
                "deployment_id": self.settings.deployment_id, "node_id": value["node_id"],
                "node_ca_pem": self.settings.ca.decode("ascii"),
                "name": value["name"], "mode": value["mode"], "expires_at": value["expires_at"],
                "secret": value["secret"]}

    def claim(self, secret, csr, node_id):
        self.configured()
        pending, receipt = self.records.claim(secret, csr, node_id)
        return {"request_id": pending["id"], "node_id": node_id, "receipt": receipt,
                "public_key": pending["public_key"], "status": pending["status"]}

    async def issue(self, identity, expected, revision, actor=None):
        self.configured()
        if self.provider is None:
            raise Failure("issuer_unavailable", "The certificate authority is unavailable.", 503)
        if self.slots.locked() or identity in self.issuing:
            raise Failure("capacity", "Wait for certificate issuance to finish.", 429)
        self.issuing.add(identity)
        pending = None
        task = None
        async with self.slots:
            try:
                if actor:
                    self.permission(actor, "contributors:manage")
                pending = self.records.begin_issue(identity, expected, revision, actor)
                node_id = pending["node_id"]
                request = {"request_id": identity, "node_id": node_id, "csr_pem": pending["csr_pem"],
                           "identity_uri": self.settings.uri(node_id), "validity_seconds": self.settings.certificate_seconds}
                task = asyncio.create_task(asyncio.to_thread(self.provider.issue, request))
                async with asyncio.timeout(21):
                    result = await asyncio.shield(task)
                if not isinstance(result, dict) or set(result) != {"certificate_chain"}:
                    raise ValueError("Invalid certificate response")
                cert = contributor_certificates.certificate(result["certificate_chain"], request["csr_pem"],
                    request["identity_uri"], node_id, self.settings.ca, self.settings.certificate_seconds)
                if actor:
                    self.permission(actor, "contributors:manage")
                return self.records.issued(pending, cert)
            except Failure:
                if pending:
                    self.records.failed(pending)
                raise
            except Exception:
                if pending:
                    self.records.failed(pending)
                raise Failure("issuer_unavailable", "The certificate could not be verified or saved. Reload before retrying.", 503) from None
            finally:
                async def release():
                    try:
                        if task is not None:
                            await asyncio.gather(task, return_exceptions=True)
                        if pending:
                            self.records.failed(pending)
                    finally:
                        self.issuing.discard(identity)
                await finish_cleanup(release())

    async def revoke_at_authority(self, certificates, reason):
        for cert in certificates:
            if self.provider is None or self.slots.locked():
                self.records.audit("contributor.ca-revoke", cert["node_id"], outcome="pending")
                continue
            async with self.slots:
                task = asyncio.create_task(asyncio.to_thread(self.provider.revoke, cert["certificate_chain"], reason))
                try:
                    async with asyncio.timeout(21):
                        await asyncio.shield(task)
                    self.records.audit("contributor.ca-revoke", cert["node_id"])
                except Exception:
                    self.records.audit("contributor.ca-revoke", cert["node_id"], outcome="failed")
                finally:
                    async def release():
                        await asyncio.gather(task, return_exceptions=True)
                    await finish_cleanup(release())

    async def activate(self, fingerprint):
        self.configured()
        node, previous = self.records.activate(fingerprint)
        if previous:
            self.sessions.pop(node["id"], None)
        await self.revoke_at_authority(previous, "superseded")
        self.records.authenticate(fingerprint)
        return {"node_id": node["id"], "activated": True, "heartbeat_seconds": self.settings.heartbeat_seconds}

    async def rotate(self, fingerprint, identity, csr):
        self.configured()
        pending = self.records.rotation(fingerprint, identity, csr)
        if pending["status"] != "issued":
            pending = await self.issue(pending["id"], pending["public_key"], pending["revision"])
        self.records.authenticate(fingerprint)
        cert = self.records.get("contributor_certificates", pending["certificate_fingerprint"])
        if cert["status"] != "pending" or cert["expires_at"] <= time.time():
            raise Failure("rotation_expired", "The pending rotation is no longer available.", 409)
        return {"request_id": identity, "certificate_chain": cert["certificate_chain"], "expires_at": cert["expires_at"]}

    async def disable(self, identity, revision, actor):
        self.permission(actor, "contributors:manage")
        node, revoked = self.records.disable(identity, revision, actor)
        self.sessions.pop(identity, None)
        await self.revoke_at_authority(revoked, "disabled")
        self.permission(actor, "contributors:manage")
        return node

    def remove(self, identity, revision, actor):
        self.permission(actor, "contributors:manage")
        result = self.records.remove(identity, revision, actor)
        self.sessions.pop(identity, None)
        return result

    def guard(self, identity, session_id, fingerprint):
        self.records.authenticate(fingerprint)
        self.connection(identity, session_id, fingerprint)

    def connection(self, identity, session_id, fingerprint):
        current = self.sessions.get(identity)
        if (not current or current["id"] != session_id or current["fingerprint"] != fingerprint
                or current["deadline"] <= time.monotonic()
                or time.monotonic() - current["verified_at"] > self.settings.lease_seconds):
            raise Failure("node_lease_expired", "The contributor connection lease expired or was replaced.", 403)

    def heartbeat(self, fingerprint, message, transport):
        self.configured()
        node, cert = self.records.authenticate(fingerprint)
        now = time.monotonic()
        current = self.sessions.get(node["id"])
        if message.session_id is None:
            if message.sequence != 1:
                raise Failure("invalid_sequence", "A new contributor channel starts at sequence one.", 409)
            current = {"id": secrets.token_hex(16), "fingerprint": fingerprint, "sequence": 0,
                       "deadline": now, "verified_at": now}
            self.sessions[node["id"]] = current
        else:
            self.connection(node["id"], message.session_id, fingerprint)
        assert current is not None
        if message.sequence not in {current["sequence"], current["sequence"] + 1}:
            raise Failure("invalid_sequence", "The contributor message sequence is not current.", 409)
        if message.sequence > current["sequence"]:
            current.update(sequence=message.sequence, deadline=now + min(self.settings.lease_seconds, cert["expires_at"] - time.time()),
                           sample=message.sample.model_dump(), transport=transport, seen=time.time())
        current["verified_at"] = now
        self.connection(node["id"], current["id"], fingerprint)
        return {"version": 1, "node_id": node["id"], "session_id": current["id"],
                "sequence": current["sequence"], "lease_seconds": max(0, current["deadline"] - time.monotonic()),
                "heartbeat_seconds": self.settings.heartbeat_seconds,
                "execution_available": self.service.workloads.runner.available(node["id"])}
