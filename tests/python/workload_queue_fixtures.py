# SPDX-License-Identifier: Apache-2.0
"""Provide explicit synthetic executor receipts for controller workflow regressions."""

import base64
import json
import secrets
import time
from collections import Counter
from types import SimpleNamespace

from test_execution_ledger import offer

from ficc.errors import Failure
from ficc.execution.spec import digest
from ficc.execution.wire import REPLY
from ficc.workloads import provider


class SyntheticExecutor:
    def __init__(self, queue, node, count):
        self.queue, self.node = queue, node
        self.installation = secrets.token_hex(16)
        self.ledger_id = secrets.token_hex(16)
        self.offer = offer(count).model_copy(update={"projects": [node["project_id"]], "mode": node["mode"]})
        self.attempts, self.plans = {}, {}
        self.starts = Counter()
        self.finish = False
        self.drop_start = False
        self.fingerprint = secrets.token_hex(32)
        self.session = {"id": secrets.token_hex(16), "fingerprint": self.fingerprint,
                        "deadline": time.monotonic() + 30, "verified_at": time.monotonic()}
        queue.service.contributors.settings = SimpleNamespace(deployment_id="b" * 32, lease_seconds=30)
        queue.service.contributors.sessions[node["id"]] = self.session

    def pulse(self):
        self.session.update(deadline=time.monotonic() + 30, verified_at=time.monotonic())

    def authenticate(self, fingerprint):
        assert fingerprint == self.fingerprint
        node = self.queue.service.contributors.records.get("contributors", self.node["id"])
        if node["disabled"]:
            raise Failure("contributor_disabled", "The synthetic contributor is disabled.", 403)
        return node, {}

    def snapshot(self):
        held = any(item["state"] != "released" for item in self.attempts.values())
        available = self.offer.limits.model_dump()
        if held:
            available.update(storage_bytes=0, storage_inodes=0, gpu_devices=[])
        return {"installation_id": self.installation, "ledger_id": self.ledger_id, "admission_version": 1,
                "deployment_id": "b" * 32,
                "node_id": self.node["id"], "maximum_lease_seconds": 30,
                "offer": self.offer.model_dump(), "capacity": {
                    "slots": [{"id": "synthetic-slot", "generation": 1, "storage_bytes": 268435456,
                               "storage_inodes": 16384, "available": not held, "reason": None}],
                    "providers": [{"id": self.offer.runtimes[0].provider, "package_digest": self.offer.runtimes[0].package_digest,
                                   "available": True, "reason": None}], "available": available},
                "attempts": [self.attempts[key].copy() for key in sorted(self.attempts)], "next": None}

    async def request(self, identity, message, check, **_kwargs):
        assert identity == self.node["id"]
        check()
        envelope = {"version": 1, "id": message.id, "deployment_id": "b" * 32, "node_id": identity, "ok": True}
        if message.action == "snapshot":
            snapshot = self.snapshot()
            snapshot["attempts"] = [item for item in snapshot["attempts"] if message.after is None or item["attempt_id"] > message.after][:64]
            snapshot["next"] = snapshot["attempts"][-1]["attempt_id"] if len(snapshot["attempts"]) == 64 else None
            return REPLY.validate_python({**envelope, "snapshot": snapshot})
        if message.action == "prepare":
            assert (message.installation_id, message.ledger_id, message.admission_version) == (
                self.installation, self.ledger_id, 1)
            for admission in message.attempts:
                plan, lease = admission.plan, admission.lease
                assert plan.attempt_id not in self.attempts
                self.plans[plan.attempt_id] = plan
                self.attempts[plan.attempt_id] = {"attempt_id": plan.attempt_id, "generation": plan.generation,
                    "plan_digest": plan.digest(), "state": "prepared", "reason": None, "exit_code": None,
                    "output_bytes": 0, "error_bytes": 0, "cleanup_confirmed": False,
                    "job_id": plan.job_id, "project_id": plan.project_id, "offer_revision": plan.offer_revision,
                    "lease_sequence": lease.sequence, "lease_expires_at": lease.expires_at, "ready": False, "outcome": None}
            ids = [item.plan.attempt_id for item in message.attempts]
        elif message.action == "reject_absent":
            assert (message.installation_id, message.ledger_id, message.admission_version) == (
                self.installation, self.ledger_id, 1)
            ids = [plan.attempt_id for plan in message.plans]
            for plan in message.plans:
                if plan.attempt_id in self.attempts:
                    assert self.plans[plan.attempt_id] == plan
                    continue
                self.plans[plan.attempt_id] = plan
                self.attempts[plan.attempt_id] = {"attempt_id": plan.attempt_id, "generation": plan.generation,
                    "plan_digest": plan.digest(), "state": "failed", "reason": "admission_rejected", "exit_code": None,
                    "output_bytes": 0, "error_bytes": 0, "cleanup_confirmed": True,
                    "job_id": plan.job_id, "project_id": plan.project_id, "offer_revision": plan.offer_revision,
                    "lease_sequence": 0, "lease_expires_at": 0, "ready": False, "outcome": "failed"}
        else:
            rows = message.leases if message.action == "renew" else message.reads if message.action == "collect" else message.attempts
            ids = [item.attempt_id for item in rows]
            for row in rows:
                item = self.attempts[row.attempt_id]
                assert row.generation == item["generation"] and row.plan_digest == item["plan_digest"]
                if message.action == "renew":
                    item.update(lease_sequence=row.sequence, lease_expires_at=row.expires_at)
                elif message.action == "start":
                    self.starts[row.attempt_id] += 1
                    assert self.starts[row.attempt_id] == 1
                    item.update(state="running", ready=True)
                elif message.action == "observe":
                    item["ready"] = True
                    if self.finish and item["state"] == "running":
                        index = int(self.plans[row.attempt_id].job.payload.argv[1])
                        state = ("succeeded", "failed", "cancelled", "unknown")[index % 4]
                        item.update(state=state, exit_code=0 if state == "succeeded" else 1 if state == "failed" else None,
                                    cleanup_confirmed=True, outcome=state, output_bytes=len(self.output(row.attempt_id)))
                elif message.action == "stop":
                    item.update(state="cancelled", cleanup_confirmed=True, outcome="cancelled")
                elif message.action == "release":
                    assert item["cleanup_confirmed"]
                    item["state"] = "released"
        if message.action == "start" and self.drop_start:
            self.drop_start = False
            raise Failure("executor_reply_unknown", "Synthetic lost start reply.", 504)
        if message.action == "collect":
            results = []
            for row in message.reads:
                data = self.output(row.attempt_id)
                part = data[row.offset:row.offset + row.length]
                results.append({**row.model_dump(exclude={"length"}), "ok": True, "data": base64.b64encode(part).decode(),
                    "next_offset": row.offset + len(part), "total_bytes": len(data), "eof": row.offset + len(part) == len(data),
                    "complete": self.attempts[row.attempt_id]["cleanup_confirmed"], "identity": digest(list(data))})
        else:
            results = [{key: self.attempts[identity][key] for key in ("attempt_id", "generation", "plan_digest")}
                       | {"ok": True, "attempt": self.attempts[identity].copy()} for identity in ids]
        check()
        return REPLY.validate_python({**envelope, "results": results})

    def output(self, identity):
        plan = self.plans[identity]
        return ("synthetic-output:" + plan.job_id + ":" + plan.job.payload.argv[1]).encode()


def scheduler(queue, capacity=1):
    path = queue.service.settings.state_dir / "workload-provider.json"
    path.write_text(json.dumps({"provider": "fair", "configuration": {"global_active": capacity, "project_active": capacity}}))
    path.chmod(0o600)
    queue.scheduler = provider.load(queue.service.settings.state_dir)
