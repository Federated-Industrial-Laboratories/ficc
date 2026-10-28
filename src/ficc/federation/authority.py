# SPDX-License-Identifier: Apache-2.0
"""Explicit resource grants remain subordinate to local identity and project policy."""
import asyncio
import secrets
import time

from ..errors import Failure
from .schema import GrantSpec

SCOPES = {
    "discover": {"inference:read"},
    "inference:invoke": {"inference:invoke"},
    "inference:manage": {"inference:read", "inference:manage", "models:read", "jobs:execute", "jobs:cancel", "contributors:read"},
    "models:read": {"models:read"},
    "models:transfer": {"models:read"},
    "models:manage": {"models:read", "models:manage"},
    "resources:read": {"contributors:read"},
}


class Authority:
    def __init__(self, manager):
        self.manager = manager
        self.active: dict[str, set[asyncio.Task]] = {}

    def create(self, peer, spec, actor):
        m = self.manager
        actor = m.current(actor, "federation:manage")
        spec = GrantSpec.model_validate(spec)
        scopes = set().union(*(SCOPES[s] for s in spec.scopes))
        for scope in scopes:
            actor.require(scope)
        for identity in spec.services:
            m.service.inference.get(identity, actor)
        for identity in spec.models:
            m.service.models.get(identity, actor)
        for identity in spec.nodes:
            m.service.workloads.authority.node(actor.project_id, identity)
        # The random bearer is discarded. Only the receiving controller uses its
        # credential ID, after the separate peer, grant and resource checks below.
        with m.service.store.lock, m.service.store.db:
            _, credential = m.service.auth.issue("token", "Federation " + peer["cluster"]["label"],
                sorted(scopes), lifetime=spec.lifetime, subject_id=actor.subject_id, project_id=actor.project_id)
            value = {"id": secrets.token_hex(16), "project_id": actor.project_id,
                     "subject_id": actor.subject_id, "peer": peer["id"], "credential": credential.id,
                     "spec": spec.model_dump(), "generation": 1, "state": "active",
                     "expires": credential.expires_at, "used_requests": 0, "used_bytes": 0,
                     "created_services": [], "created_models": []}
            m.grants.save(value)
            m.service.store.audit("federation.grant", value["id"], actor=actor.id,
                                  subject_id=actor.subject_id, project_id=actor.project_id)
        return value

    def check(self, identity, peer, generation, scope=None, resource=None):
        m = self.manager
        value = m.grants.get(identity)
        current_peer = m.peers.get(peer["id"])
        if (current_peer["state"] != "paired" or current_peer["cluster"] != peer["cluster"]
                or value["peer"] != peer["id"] or value["state"] != "active"
                or value["generation"] != generation or value["expires"] <= time.time()):
            raise Failure("federation_grant", "The peer grant is inactive, expired or has changed.", 403)
        spec = value["spec"]
        if scope and scope not in spec["scopes"]:
            raise Failure("federation_denied", "This peer grant does not permit the operation.", 403)
        if resource is not None:
            kind, identity = resource
            permitted = spec[kind]
            if kind == "services":
                permitted = permitted + value["created_services"]
            elif kind == "models":
                permitted = permitted + value.get("created_models", [])
            if identity not in permitted:
                raise Failure("federation_denied", "This resource is not published in the peer grant.", 403)
        actor = m.service.auth.current(value["credential"])
        for local in SCOPES.get(scope, set()):
            actor.require(local)
        return value, actor

    def admit(self, request, peer):
        with self.manager.service.store.lock, self.manager.service.store.db:
            value, actor = self.check(request.grant, peer, request.generation)
            active = self.active.setdefault(value["id"], set())
            if len(active) >= value["spec"]["concurrent"] or value["used_requests"] >= value["spec"]["requests"]:
                raise Failure("federation_quota", "The peer's concurrent or request allowance is exhausted.", 429)
            value["used_requests"] += 1
            self.manager.grants.save(value)
            task = asyncio.current_task()
            if task is None:
                raise RuntimeError("Federation admission requires an owned task.")
            active.add(task)
        return value, actor

    def release(self, identity):
        active = self.active.get(identity)
        if active is not None:
            active.discard(asyncio.current_task())
            if not active:
                self.active.pop(identity, None)

    def charge(self, identity, peer, generation, count):
        with self.manager.service.store.lock, self.manager.service.store.db:
            value, _ = self.check(identity, peer, generation, "models:transfer")
            if count < 0 or value["used_bytes"] + count > value["spec"]["transfer_bytes"]:
                raise Failure("federation_quota", "The peer's model transfer allowance is exhausted.", 429)
            value["used_bytes"] += count
            self.manager.grants.save(value)

    async def revoke(self, identity, actor):
        m = self.manager
        actor = m.current(actor, "federation:manage")
        value = m.grants.get(identity)
        actor.require_record(value)
        if value["state"] != "revoked":
            value.update(state="revoked", generation=value["generation"]+1)
            m.grants.save(value)
        m.service.auth.revoke(value["credential"], actor.id)
        tasks = list(self.active.get(identity, ()))
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if value["spec"]["stop_on_revoke"]:
            # Restrictive cleanup is intrinsic to this exact creation grant. It
            # does not require an expired bearer or broader revoker permissions.
            async with m.service.inference.lock:
                with m.service.store.lock, m.service.store.db:
                    for service in m.service.inference.records.all(value["project_id"]):
                        if service["project_id"] != value["project_id"] or service["actor"] != value["credential"]:
                            continue
                        service.update(desired="stopped", state="draining", revision=service["revision"]+1)
                        for job_id in service["workloads"]:
                            job = m.service.workloads.records.get(job_id)
                            m.service.workloads.records.cancel(job_id, job.revision)
                            m.service.workloads.inputs.discard_job(job_id)
                        m.service.inference.records.save(service)
        m.service.store.audit("federation.revoke", identity, actor=actor.id,
                              subject_id=actor.subject_id, project_id=actor.project_id)
        return value
