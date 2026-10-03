# SPDX-License-Identifier: Apache-2.0
"""Bind executor observations to stored plans and preserve uncertain dispatch outcomes."""

import secrets
import time

from ..errors import Failure
from ..execution.protocol import MESSAGE
from ..execution.spec import AttemptResult, Fence
from ..execution.wire import BatchReply, FailureReply, Refused, Result, SnapshotReply
from .schema import TERMINAL


def fence(attempt):
    return Fence(attempt_id=attempt.id, generation=attempt.plan.generation, plan_digest=attempt.plan.digest()).model_dump()


class Commands:
    def __init__(self, queue):
        self.queue = queue
        self.observed: dict[str, dict] = {}

    async def call(self, node_id, action, fields, check=lambda: None):
        message = MESSAGE.validate_python({"version": 1, "id": secrets.token_hex(16), "action": action, **fields})
        reply = await self.queue.channel.request(node_id, message, check)
        if isinstance(reply, FailureReply):
            raise Failure(reply.error.code, reply.error.message, 409)
        return reply

    async def snapshot(self, node_id, *, after=None):
        reply = await self.call(node_id, "snapshot", {"after": after})
        if not isinstance(reply, SnapshotReply):
            raise Failure("executor_response", "The executor did not return the requested capacity snapshot.", 502)
        snapshot = reply.snapshot
        node = self.queue.service.contributors.records.get("contributors", node_id)
        if (snapshot.node_id != node_id or snapshot.deployment_id != reply.deployment_id
                or snapshot.offer.mode != node["mode"]):
            raise Failure("executor_identity", "The executor capacity does not bind the approved contributor.", 409)
        ids = [item.attempt_id for item in snapshot.attempts]
        if (ids != sorted(set(ids)) or after and any(identity <= after for identity in ids)
                or snapshot.next is not None and (not ids or snapshot.next != ids[-1])):
            raise Failure("executor_response", "The executor snapshot has an invalid attempt cursor.", 502)
        return snapshot

    def observation(self, result, snapshot):
        records = self.queue.records
        stored = records.attempt(result.attempt_id)
        plan = stored.plan
        if stored.ledger_id is not None and (stored.ledger_id, stored.admission_version) != (
                snapshot.ledger_id, snapshot.admission_version):
            raise Failure("executor_replaced", "The result belongs to another executor admission ledger.", 409)
        if (result.job_id != plan.job_id or result.project_id != plan.project_id or result.offer_revision != plan.offer_revision
                or result.lease_sequence > stored.lease.sequence or result.lease_expires_at > stored.lease.expires_at):
            raise Failure("attempt_changed", "The executor result does not bind the admitted workload or lease.", 409)
        fields = result.model_dump(include=set(AttemptResult.model_fields))
        if result.state == "released" and stored.state != "released":
            if result.outcome not in TERMINAL | {"unknown"}:
                raise Failure("executor_response", "The released attempt has no retained outcome.", 502)
            records.observation(AttemptResult.model_validate({**fields, "state": result.outcome}),
                                snapshot.node_id, snapshot.installation_id)
        value = records.observation(AttemptResult.model_validate(fields), snapshot.node_id, snapshot.installation_id)
        self.observed[value.id] = {**self.observed.get(value.id, {}), "ready": result.ready, "at": time.monotonic()}
        return value

    async def batch(self, node_id, snapshot, action, attempts, *, fields=None, check=lambda: None):
        if not attempts:
            return []
        wanted = [fence(item) for item in attempts]
        try:
            reply = await self.call(node_id, action, fields if fields is not None else {"attempts": wanted}, check)
            if not isinstance(reply, BatchReply) or len(reply.results) != len(wanted):
                raise Failure("executor_response", "The executor returned an invalid batch result.", 502)
            for row, expected in zip(reply.results, wanted, strict=True):
                if row.model_dump(include=set(Fence.model_fields)) != expected:
                    raise Failure("executor_response", "The executor result order or attempt binding changed.", 502)
                if row.ok and (not isinstance(row, Result) or row.attempt.model_dump(include=set(Fence.model_fields)) != expected):
                    raise Failure("executor_response", "The executor result does not contain the requested attempt.", 502)
            output = []
            for row in reply.results:
                if isinstance(row, Result):
                    output.append(self.observation(row.attempt, snapshot))
                elif isinstance(row, Refused):
                    self.uncertain(row.attempt_id, row.error.code)
            return output
        except (Failure, OSError, ValueError):
            for item in attempts:
                self.uncertain(item.id, "executor_reply_unknown")
            raise

    def uncertain(self, identity, reason):
        attempt = self.queue.records.attempt(identity)
        self.observed.pop(identity, None)
        if attempt.state in {"preparing", "prepared", "starting", "running"}:
            self.queue.records.transition(identity, attempt.state, "unknown", reason)
