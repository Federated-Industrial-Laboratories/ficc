# SPDX-License-Identifier: Apache-2.0
"""Expose project-scoped durable jobs, current node offers, and explicit recovery actions."""

import asyncio
import base64
import binascii
import secrets

from ..audit_sdk import digest as audit_digest
from ..errors import Failure
from ..execution.protocol import Collect, Read
from ..execution.spec import Fence
from ..execution.wire import BatchReply, ReadResult
from . import provider
from .artifacts import Publications
from .authority import Authority
from .channel import Channel
from .commands import Commands, fence
from .inputs import Inputs
from .node_records import Nodes
from .records import Records
from .runner import Runner
from .schema import TERMINAL


class Queue:
    def __init__(self, service):
        self.service = service
        self.records, self.nodes = Records(service.store), Nodes(service.store)
        self.authority = Authority(service)
        self.scheduler = provider.load(service.settings.state_dir)
        self.channel = Channel(service)
        self.commands = Commands(self)
        self.inputs = Inputs(self)
        self.artifacts = Publications(self)
        self.runner = Runner(self)
        self.readers = asyncio.Semaphore(8)

    def close(self):
        self.inputs.stop()
        self.channel.close()
        if self.scheduler is not None:
            self.scheduler.close()

    def suspended(self):
        return self.service.store.get_setting("workloads.suspended", False)

    def actor(self, actor, scope):
        current = self.service.auth.current(actor.id)
        current.require(scope)
        if current.project_id != actor.project_id or current.node_ids is not None or current.root_ids is not None:
            raise Failure("denied", "Contributor jobs require an unrestricted credential within their project.", 403)
        return current

    def owned(self, identity, actor, scope):
        current = self.actor(actor, scope)
        job = self.records.get(identity)
        if job.project_id != current.project_id:
            raise Failure("not_found", "The workload was not found in this project.", 404)
        return job

    def view(self, job):
        attempt = self.records.attempt(job.current_attempt) if job.current_attempt else None
        return {"id": job.id, "project_id": job.project_id, "subject_id": job.subject_id, "actor": job.actor,
                "request": job.request.model_dump(), "state": job.state, "reason": job.reason,
                "generation": job.generation, "cancelled": job.cancelled, "revision": job.revision,
                "created_at": job.created_at, "updated_at": job.updated_at,
                "attempt": ({"id": attempt.id, "node_id": attempt.node_id, "generation": attempt.plan.generation,
                             "state": attempt.state, "lease_expires_at": attempt.lease.expires_at,
                             "input_progress": self.commands.observed.get(attempt.id, {}).get("inputs"),
                             "observed": attempt.observed.model_dump() if attempt.observed else None,
                             "outcome": attempt.outcome.model_dump() if attempt.outcome else None} if attempt else None)}

    def all(self, actor):
        actor = self.actor(actor, "jobs:read")
        from .usage import report
        return {"workloads": [self.view(job) for job in self.records.jobs(actor.project_id)],
                "usage": report(self.service.store, actor.project_id),
                "configured": self.scheduler is not None, "suspended": self.suspended(),
                "scheduler_error": self.runner.failed}

    def offers(self, actor):
        actor = self.actor(actor, "contributors:read")
        allowed = {node["id"] for node in self.service.contributors.records.rows("contributors")
                   if node["project_id"] == actor.project_id and not node["disabled"]}
        values = []
        for item in self.nodes.all():
            if item.snapshot.node_id not in allowed:
                continue
            value = item.model_dump()
            value["snapshot"]["offer"]["projects"] = [project for project in item.snapshot.offer.projects if project == actor.project_id]
            values.append({**value, "available": self.runner.available(item.snapshot.node_id),
                           "reason": self.runner.errors.get(item.snapshot.node_id)})
        return {"offers": values}

    async def submit(self, request, key, actor):
        self.service.live()
        if self.scheduler is None:
            raise Failure("scheduler_unavailable", "Install and configure a workload scheduler before submitting jobs.", 409)
        if self.suspended():
            raise Failure("workloads_suspended", "Workload dispatch is suspended after restore.", 409)
        delegation = self.authority.capture(actor, request)
        request = self.inputs.bind(request, delegation)
        await self.service.audit_delivery.require("workload.submit", audit_digest({"key": key, "request": request.model_dump()}), actor)
        with self.service.store.lock, self.service.store.db:
            delegation = self.authority.capture(actor, request)
            request = self.inputs.bind(request, delegation)
            result = self.records.submit(request, key, delegation)
            self.audit("workload.submit", result.id, actor)
        return self.view(result)

    def audit(self, action, identity, actor):
        self.service.store.audit(action, identity, "success", actor.id,
                                 subject_id=actor.subject_id, project_id=actor.project_id)

    def cancel(self, identity, revision, actor):
        with self.service.store.lock, self.service.store.db:
            self.owned(identity, actor, "jobs:cancel")
            result = self.records.cancel(identity, revision)
            self.inputs.discard_job(identity)
            self.audit("workload.cancel", identity, actor)
        return self.view(result)

    async def retry(self, identity, revision, actor, *, acknowledge_unknown=False):
        self.owned(identity, actor, "jobs:execute")
        await self.service.audit_delivery.require("workload.retry", audit_digest({"id": identity, "revision": revision,
                                                  "acknowledge_unknown": acknowledge_unknown}), actor)
        with self.service.store.lock, self.service.store.db:
            job = self.owned(identity, actor, "jobs:execute")
            # A new delegation belongs to the original submitter; another user submits a separate job.
            if job.subject_id != actor.subject_id:
                raise Failure("denied", "Only the original submitter can retry this workload.", 403)
            delegation = self.authority.capture(actor, job.request)
            self.inputs.bind(job.request, delegation)
            result = self.records.retry(identity, revision, delegation, acknowledge_unknown=acknowledge_unknown)
            self.audit("workload.retry", identity, actor)
        return self.view(result)

    async def release(self, identity, revision, actor):
        job = self.owned(identity, actor, "jobs:cancel")
        if job.revision != revision or job.state not in TERMINAL | {"unknown"} or job.current_attempt is None:
            raise Failure("workload_unresolved", "Reload a completed or stopped workload before releasing its output.", 409)
        attempt = self.records.attempt(job.current_attempt)
        self.artifacts.require_releasable(identity)
        if attempt.state == "abandoned":
            raise Failure("attempt_abandoned", "An abandoned attempt cannot reclaim storage through the revoked node identity.", 409)
        if attempt.state == "released":
            return self.view(job)
        if not attempt.observed or not attempt.observed.cleanup_confirmed:
            raise Failure("workload_unresolved", "Observe empty workload processes before releasing output or capacity.", 409)
        if self.runner.lock(attempt.node_id).locked():
            raise Failure("executor_busy", "Wait for the current contributor update to finish.", 409)
        async with self.runner.lock(attempt.node_id):
            snapshot = self.runner.live.get(attempt.node_id)
            if not snapshot or not self.runner.available(attempt.node_id):
                raise Failure("executor_unavailable", "Reconnect the executor before releasing its output.", 409)
            def check():
                current = self.owned(identity, actor, "jobs:cancel")
                self.artifacts.require_releasable(identity)
                if current.current_attempt != attempt.id:
                    raise Failure("attempt_changed", "The workload attempt changed before output release.", 409)
            await self.commands.batch(attempt.node_id, snapshot[0], "release", [attempt], check=check)
        self.audit("workload.release", identity, actor)
        return self.view(self.owned(identity, actor, "jobs:cancel"))

    def remove(self, identity, revision, actor):
        with self.service.store.lock, self.service.store.db:
            self.owned(identity, actor, "jobs:cancel")
            self.artifacts.require_releasable(identity, removing=True)
            self.records.remove(identity, revision)
            self.audit("workload.remove", identity, actor)
        return {"id": identity, "removed": True}

    def abandon(self, identity, revision, actor, acknowledge_unknown):
        if not acknowledge_unknown:
            raise Failure("acknowledgement_required", "Acknowledge that execution effects and local cleanup remain unresolved.", 409)
        with self.service.store.lock, self.service.store.db:
            self.owned(identity, actor, "jobs:cancel")
            self.actor(actor, "contributors:manage")
            self.artifacts.require_releasable(identity)
            result = self.records.abandon(identity, revision)
            self.audit("workload.abandon", identity, actor)
        return self.view(result)

    async def collect(self, identity, reads, actor):
        job = self.owned(identity, actor, "jobs:logs")
        if job.current_attempt is None:
            raise Failure("output_unavailable", "This workload has no execution output.", 409)
        attempt = self.records.attempt(job.current_attempt)
        if attempt.state in {"released", "abandoned"}:
            raise Failure("output_released", "Output is unavailable for a released or abandoned attempt.", 409)
        command = Collect(version=1, id=secrets.token_hex(16), action="collect",
            reads=[Read(**fence(attempt), **item.model_dump()) for item in reads])
        if self.readers.locked() or self.runner.lock(attempt.node_id).locked():
            raise Failure("executor_busy", "Wait for a contributor read or update to finish.", 409)
        def check():
            current = self.owned(identity, actor, "jobs:logs")
            if current.current_attempt != attempt.id:
                raise Failure("attempt_changed", "The workload attempt changed during the output read.", 409)
        async with self.readers, self.runner.lock(attempt.node_id):
            reply = await self.channel.request(attempt.node_id, command, check)
            if not isinstance(reply, BatchReply) or len(reply.results) != len(command.reads):
                raise Failure("executor_response", "The executor returned an invalid output batch.", 502)
            for item, requested in zip(reply.results, command.reads, strict=True):
                if (not isinstance(item, ReadResult) or item.model_dump(include=set(Fence.model_fields)) != fence(attempt)
                        or item.object != requested.object or item.offset != requested.offset):
                    raise Failure("executor_response", "The returned bytes do not bind the requested output.", 502)
                try:
                    size = len(base64.b64decode(item.data, validate=True))
                except (ValueError, binascii.Error):
                    raise Failure("executor_response", "The executor returned an invalid byte encoding.", 502) from None
                if (size > requested.length or item.next_offset != item.offset + size or item.next_offset > item.total_bytes
                        or item.eof != (item.next_offset == item.total_bytes)):
                    raise Failure("executor_response", "The executor output range is invalid.", 502)
            check()
            return {"attempt_id": attempt.id, "results": [item.model_dump() for item in reply.results]}
