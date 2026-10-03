# SPDX-License-Identifier: Apache-2.0
"""Reconcile contributors, renew current authority, and dispatch admitted queue entries."""

import asyncio
import secrets
import sqlite3
import time

from ..errors import Failure
from ..execution.spec import Plan, Renewal
from . import provider
from .schema import TERMINAL


class Runner:
    def __init__(self, queue):
        self.queue = queue
        self.reconciled: dict[str, tuple] = {}
        self.live: dict[str, tuple] = {}
        self.errors: dict[str, str] = {}
        self.deferred: dict[str, float] = {}
        self.locks: dict[str, asyncio.Lock] = {}
        self.capacity = asyncio.Semaphore(8)
        self.failed = False
        self.transferring: set[str] = set()

    def lock(self, identity):
        return self.locks.setdefault(identity, asyncio.Lock())

    def available(self, identity):
        current = self.live.get(identity)
        if current is None or time.monotonic() - current[1] > current[0].maximum_lease_seconds:
            return False
        try:
            session = self.queue.channel.session(identity)
        except Failure:
            return False
        return self.reconciled.get(identity) == (session["id"], current[0].installation_id, current[0].ledger_id)

    def authority(self, attempt, *, starting=False):
        queue = self.queue
        if queue.suspended():
            raise Failure("workloads_suspended", "Workload dispatch is suspended after restore.", 409)
        job = queue.records.get(attempt.job_id)
        queue.authority.check(job, attempt.node_id, enforcement=True)
        if not self.available(attempt.node_id):
            raise Failure("executor_unavailable", "The executor has no reconciled current capacity.", 409)
        snapshot = self.live[attempt.node_id][0]
        if snapshot.installation_id != attempt.installation_id:
            raise Failure("executor_replaced", "The executor installation changed.", 409)
        if attempt.ledger_id is not None and (snapshot.ledger_id, snapshot.admission_version) != (
                attempt.ledger_id, attempt.admission_version):
            raise Failure("executor_replaced", "The executor admission ledger changed.", 409)
        if starting and snapshot.offer.revision != attempt.plan.offer_revision:
            raise Failure("offer_changed", "The local offer changed before dispatch.", 409)
        if reason := snapshot.offer.refusal(job.project_id, job.request.job, time.time(), continuing=not starting):
            raise Failure(reason, "The current local offer does not permit this workload.", 409)

    async def reconcile(self, identity, snapshot):
        queue = self.queue
        current = queue.channel.session(identity)
        binding = (current["id"], snapshot.installation_id, snapshot.ledger_id)
        if self.reconciled.get(identity) == binding:
            return
        missing = {item.id for item in queue.records.attempts(identity) if item.state not in {"released", "abandoned"}}
        page = snapshot
        cursor = ""
        while True:
            if (page.installation_id, page.ledger_id, page.admission_version, page.offer) != (
                    snapshot.installation_id, snapshot.ledger_id, snapshot.admission_version, snapshot.offer):
                raise Failure("executor_changed", "The executor changed while reconciling its attempts.", 409)
            for result in page.attempts:
                if result.attempt_id <= cursor:
                    raise Failure("executor_response", "The executor attempt cursor did not advance.", 502)
                cursor = result.attempt_id
                missing.discard(result.attempt_id)
                try:
                    attempt = queue.records.attempt(result.attempt_id)
                except Failure as exc:
                    if exc.code != "not_found":
                        raise
                    if result.state not in TERMINAL | {"released"}:
                        await queue.commands.call(identity, "stop", {"attempts": [result.model_dump(include={"attempt_id", "generation", "plan_digest"})]})
                    continue
                if attempt.state not in {"released", "abandoned"}:
                    queue.commands.observation(result, snapshot)
            if page.next is None:
                break
            if not page.attempts or page.next != cursor:
                raise Failure("executor_response", "The executor attempt cursor differs from its page.", 502)
            page = await queue.commands.snapshot(identity, after=page.next)
        for attempt_id in missing:
            queue.commands.uncertain(attempt_id, "attempt_not_observed")
        self.reconciled[identity] = binding

    async def reject_absent(self, identity, snapshot, attempts):
        candidates = [item for item in attempts if item.state == "unknown" and item.observed is None
                      and not item.start_requested and item.admission_version == snapshot.admission_version == 1
                      and (item.installation_id, item.ledger_id) == (snapshot.installation_id, snapshot.ledger_id)]
        for offset in range(0, len(candidates), 64):
            values = candidates[offset:offset + 64]
            await self.queue.commands.batch(identity, snapshot, "reject_absent", values, fields={
                "installation_id": snapshot.installation_id, "ledger_id": snapshot.ledger_id,
                "admission_version": 1, "plans": [item.plan.model_dump() for item in values]})

    async def node(self, identity):
        if self.lock(identity).locked():
            return
        queue = self.queue
        async with self.lock(identity), self.capacity:
            try:
                snapshot = await queue.commands.snapshot(identity)
                queue.nodes.save(snapshot)
                await self.reconcile(identity, snapshot)
                self.live[identity] = (snapshot, time.monotonic())
                attempts = [item for item in queue.records.attempts(identity) if item.state not in {"released", "abandoned"}]
                await self.reject_absent(identity, snapshot, attempts)
                for offset in range(0, len(attempts), 64):
                    await queue.commands.batch(identity, snapshot, "observe", attempts[offset:offset + 64])
                await self.advance(identity, snapshot)
                if await queue.inputs.advance(identity, queue.records.attempts(identity)):
                    self.transferring.add(identity)
                else:
                    self.transferring.discard(identity)
                self.errors.pop(identity, None)
            except (Failure, OSError, ValueError, sqlite3.Error) as exc:
                queue.inputs.discard_node(identity)
                self.transferring.discard(identity)
                self.live.pop(identity, None)
                self.errors[identity] = exc.code if isinstance(exc, Failure) else "executor_unavailable"

    async def advance(self, identity, snapshot):
        queue = self.queue
        stop, renew, start = [], [], []
        for attempt in queue.records.attempts(identity):
            if attempt.state in TERMINAL | {"released", "abandoned"}:
                continue
            if attempt.state == "unknown":
                if not attempt.observed or not attempt.observed.cleanup_confirmed:
                    stop.append(attempt)
                continue
            try:
                self.authority(attempt, starting=attempt.state == "prepared")
                if attempt.lease.expires_at <= time.time():
                    raise Failure("lease_expired", "The attempt lease expired before renewal.", 409)
            except Failure:
                stop.append(attempt)
                continue
            if attempt.lease.expires_at - time.time() < snapshot.maximum_lease_seconds * 0.6:
                renew.append(attempt)
            if (attempt.state == "prepared" and not attempt.start_requested
                    and queue.commands.observed.get(attempt.id, {}).get("ready")):
                start.append(attempt)
        for action, attempts in (("stop", stop), ("renew", renew), ("start", start)):
            for offset in range(0, len(attempts), 64):
                values = attempts[offset:offset + 64]
                def check():
                    if action != "stop":
                        for attempt in values:
                            self.authority(attempt, starting=action == "start")
                check()
                fields = None
                if action == "renew":
                    leases = [queue.records.renew(item.id, time.time() + snapshot.maximum_lease_seconds - 0.5) for item in values]
                    fields = {"leases": [lease.model_dump() for lease in leases]}
                if action == "start":
                    values = [queue.records.transition(item.id, "prepared", "starting") for item in values]
                await queue.commands.batch(identity, snapshot, action, values, fields=fields, check=check)

    def placement(self, job, identity):
        queue = self.queue
        if not self.available(identity):
            raise Failure("executor_unavailable", "The contributor has no current executor capacity.", 409)
        snapshot = self.live[identity][0]
        if snapshot.admission_version != 1 or snapshot.ledger_id is None:
            raise Failure("executor_upgrade_required", "The executor needs durable admission support before new jobs can start.", 409)
        revision = queue.authority.check(job, identity, enforcement=True)
        if reason := snapshot.offer.refusal(job.project_id, job.request.job, time.time()):
            raise Failure(reason, "The local offer does not admit this workload.", 409)
        runtime, limits = job.request.job.runtime, job.request.job.limits
        if not any(item.id == runtime.provider and item.package_digest == runtime.package_digest and item.available
                   for item in snapshot.capacity.providers):
            raise Failure("runtime_unavailable", "The admitted executor provider is not available.", 409)
        if not limits.fits(snapshot.capacity.available):
            raise Failure("capacity", "The contributor has insufficient available execution capacity.", 409)
        if not any(item.available and item.storage_bytes <= limits.storage_bytes and item.storage_inodes <= limits.storage_inodes
                   for item in snapshot.capacity.slots):
            raise Failure("storage_slot_unavailable", "No independently bounded storage slot fits this workload.", 409)
        plan = Plan(version=1, deployment_id=snapshot.deployment_id, node_id=identity,
            project_id=job.project_id, subject_id=job.subject_id, job_id=job.id, attempt_id=secrets.token_hex(16),
            generation=job.generation + 1, offer_revision=snapshot.offer.revision, policy_revision=revision, job=job.request.job)
        lease = Renewal(attempt_id=plan.attempt_id, generation=plan.generation, plan_digest=plan.digest(),
                        sequence=1, expires_at=time.time() + snapshot.maximum_lease_seconds - 0.5)
        return queue.records.reserve(plan, lease, snapshot.installation_id, snapshot.offer.limits,
                                     ledger_id=snapshot.ledger_id, admission_version=snapshot.admission_version)

    async def dispatch(self, identity, attempts):
        queue = self.queue
        async with self.lock(identity), self.capacity:
            snapshot = self.live[identity][0]
            try:
                def check():
                    for attempt in attempts:
                        self.authority(attempt, starting=True)
                await queue.commands.batch(identity, snapshot, "prepare", attempts,
                    fields={"installation_id": snapshot.installation_id, "ledger_id": snapshot.ledger_id,
                            "admission_version": snapshot.admission_version,
                            "attempts": [{"plan": item.plan.model_dump(), "lease": item.lease.model_dump()} for item in attempts]}, check=check)
            except (Failure, OSError, ValueError):
                self.errors[identity] = "executor_reply_unknown"

    async def schedule(self):
        queue = self.queue
        if queue.scheduler is None or queue.suspended():
            return
        now = time.monotonic()
        jobs = queue.records.jobs()
        self.deferred = {identity: deadline for identity, deadline in self.deferred.items() if deadline > now}
        pending = [job for job in jobs if job.id not in self.deferred]
        groups: dict[str, list] = {}
        examined = 0
        while pending and examined < 64:
            chosen = provider.select(queue.scheduler, pending, queue.records.attempts())[:64 - examined]
            if not chosen:
                break
            pending = [job for job in pending if job.id not in chosen]
            for job_id in chosen:
                examined += 1
                job = queue.records.get(job_id)
                reason = "executor_unavailable"
                for identity in job.request.node_ids:
                    # Refresh actual slot availability between admissions on the same node.
                    if identity in groups or self.lock(identity).locked():
                        reason = "executor_busy"
                        continue
                    try:
                        attempt = self.placement(job, identity)
                    except Failure as exc:
                        reason = exc.code
                        continue
                    groups.setdefault(identity, []).append(attempt)
                    break
                else:
                    queue.records.pending(job_id, reason)
                    self.deferred[job_id] = time.monotonic() + 2
        await asyncio.gather(*(self.dispatch(identity, values) for identity, values in groups.items()))

    async def poll(self):
        if self.queue.scheduler is None:
            return
        while True:
            try:
                self.queue.inputs.prune()
                identities = list(self.queue.service.contributors.sessions)
                await asyncio.gather(*(self.node(identity) for identity in identities))
                for attempt in self.queue.records.attempts():
                    if (attempt.state in {"preparing", "prepared", "starting", "running"}
                            and attempt.lease.expires_at <= time.time() and not self.available(attempt.node_id)):
                        self.queue.commands.uncertain(attempt.id, "executor_unavailable")
                await self.schedule()
                self.failed = False
            except (Failure, OSError, ValueError, sqlite3.Error):
                self.failed = True
            await asyncio.sleep(0 if self.transferring else 0.5)
