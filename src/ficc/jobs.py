# SPDX-License-Identifier: Apache-2.0
"""Coordinate durable job admission and bounded remote reconciliation."""

import asyncio
import copy
import secrets
import sqlite3
import time
from contextlib import suppress
from typing import TYPE_CHECKING

from ficc_node.job_spec import TERMINAL
from ficc_node.job_state import digest

from .auth import Principal
from .errors import Failure
from .job_store import JobStore

if TYPE_CHECKING:
    from .service import Service

STATES = TERMINAL | {"queued", "dispatching", "running", "cancel_requested", "unknown"}


class Jobs:
    def __init__(self, service: "Service"):
        self.service = service
        self.store = JobStore(service.store)
        self.controller = service.store.get_setting("controller_id", None) or secrets.token_hex(16)
        service.store.set_setting("controller_id", self.controller)
        self.previews: dict[str, dict] = {}
        self.preview_pending = 0
        self.admission = asyncio.Lock()
        self.locks: dict[str, asyncio.Lock] = {}
        self.workers = asyncio.Semaphore(4)
        self.tasks: set[asyncio.Task] = set()
        self.inflight: set[str] = set()
        self.retry: dict[str, float] = {}
        self.failures: dict[str, int] = {}
        self.failed = False

    def check(self, actor: str, scope: str, nodes: list[str]):
        for node_id in nodes:
            self.service.authorize(actor, scope, node_id)

    async def ready(self, node: dict, job: dict, actor: str) -> dict:
        target = {"node_id": node["id"], "name": node["name"], "ready": False, "errors": [], "warnings": []}
        try:
            def check():
                self.check(actor, "jobs:execute", [node["id"]])
            check()
            if self.store.active(node["id"]):
                raise Failure("node_busy", "A job is active or has an unknown outcome on this machine.", 409)
            caps = await self.service.ssh.job(node, {"action": "job.capabilities"}, check=check)
            if not caps.get("jobs"):
                raise Failure("jobs_unavailable", caps.get("job_error", "Upgrade the helper to enable managed jobs."), 409)
            if not caps.get("logout_persistent"):
                target["warnings"].append("This job depends on the remote login session.")
                if not job["allow_session_lifetime"]:
                    raise Failure("session_lifetime", "Accept session lifetime or configure logout persistence on the node.", 409)
            reservations = job["gpu_reservations"].get(node["id"], [])
            if reservations:
                sample = await self.service.ssh.probe(node, check=check)
                gpus = {gpu["uuid"]: gpu for gpu in sample["resources"]["gpus"]} if sample else {}
                for item in reservations:
                    gpu = gpus.get(item["uuid"])
                    if (not gpu or gpu["memory_total_bytes"] is None or gpu["memory_used_bytes"] is None
                            or item["memory_bytes"] > gpu["memory_total_bytes"] - gpu["memory_used_bytes"]):
                        raise Failure("gpu_capacity", "The requested GPU capacity is unavailable.", 409)
                target["warnings"].append("GPU reservations are advisory; other applications can use the devices.")
            target["ready"] = True
        except Failure as exc:
            if exc.status in (401, 403):
                raise
            target["errors"].append(exc.message)
        return target

    async def preview(self, request: dict, actor: str) -> dict:
        self.service.live()
        self.check(actor, "jobs:execute", request["node_ids"])
        self.previews = {key: value for key, value in self.previews.items() if value["expires_at"] > time.time()}
        if len(self.previews) + self.preview_pending >= 64:
            raise Failure("capacity", "The job preview limit was reached.", 429)
        nodes = [self.service.store.node(node_id) for node_id in request["node_ids"]]

        async def one(node):
            async with self.workers:
                return await self.ready(node, request["job"], actor)
        self.preview_pending += 1
        try:
            targets = await asyncio.gather(*(one(node) for node in nodes))
        finally:
            self.preview_pending -= 1
        preview: dict = {"preview_id": secrets.token_hex(16), "expires_at": time.time() + 120,
                   "request": copy.deepcopy(request), "targets": targets,
                   "warnings": ["Execution has the full authority of the remote account."]}
        self.previews[preview["preview_id"]] = {**preview, "actor": actor, "nodes": copy.deepcopy(nodes)}
        return preview

    async def submit(self, preview_id: str, key: str, actor: str) -> dict:
        self.service.live()
        if not 16 <= len(key) <= 128 or any(not 32 <= ord(char) <= 126 for char in key):
            raise Failure("invalid_key", "Use an Idempotency-Key with 16 to 128 printable ASCII characters.")
        async with self.admission:
            old = self.store.existing(actor, key)
            preview = self.previews.get(preview_id)
            if old:
                self.check(actor, "jobs:execute", old["request"]["node_ids"])
                if preview_id != old["preview_id"] and (preview is None or digest(preview["request"]) != old["digest"]):
                    raise Failure("idempotency_conflict", "This key belongs to another request.", 409)
                return old
            if not preview or preview["actor"] != actor or preview["expires_at"] <= time.time():
                raise Failure("preview_expired", "Create a new job preview.", 409)
            request = preview["request"]
            self.check(actor, "jobs:execute", request["node_ids"])
            if any(not target["ready"] for target in preview["targets"]):
                raise Failure("targets_unavailable", "Resolve all target errors before submission.", 409)
            if any(self.store.active(node) for node in request["node_ids"]):
                raise Failure("node_busy", "A selected machine already has an active or unknown job.", 409)
            for snapshot in preview["nodes"]:
                current = self.service.store.node(snapshot["id"])
                if any(current.get(key) != snapshot.get(key) for key in ("host", "account", "port", "key", "profile")):
                    raise Failure("target_changed", "A selected machine changed. Create a new preview.", 409)
            operation = {"id": secrets.token_hex(16), "action": "job.submit", "actor": actor,
                         "created_at": time.time(), "updated_at": time.time(), "request": copy.deepcopy(request),
                         "digest": digest(request), "policy_revision": 1, "key": key, "preview_id": preview_id,
                         "targets": [{"node_id": node["id"], "name": node["name"], "job_id": secrets.token_hex(16),
                                      "state": "queued", "error": None, "result": None,
                                      "requested_limits": request["job"]["limits"], "effective_limits": None,
                                      "reservations": request["job"]["gpu_reservations"].get(node["id"], []),
                                      "session_lifetime": None, "node": node} for node in preview["nodes"]]}
            self.store.insert(operation)
            self.service.store.audit("job.submit", operation["id"], "queued", actor)
            return operation

    def view(self, operation: dict, actor: Principal) -> dict:
        result = copy.deepcopy(operation)
        result["targets"] = [target for target in result["targets"] if actor.node_ids is None or target["node_id"] in actor.node_ids]
        ids = [target["node_id"] for target in result["targets"]]
        result["request"]["node_ids"] = ids
        result["request"]["job"]["gpu_reservations"] = {node: reservations for node, reservations in result["request"]["job"]["gpu_reservations"].items() if node in ids}
        for target in result["targets"]:
            for field in ("node", "cancel_actor", "cancel_force"):
                target.pop(field, None)
        return {key: result[key] for key in ("id", "action", "actor", "created_at", "updated_at", "request", "targets")}

    def update(self, operation_id: str, node_id: str, values: dict):
        operation = self.store.get(operation_id)
        target = next(target for target in operation["targets"] if target["node_id"] == node_id)
        target.update(values)
        self.store.save(operation)

    async def reconcile(self, operation_id: str, node_id: str):
        async with self.workers:
            operation = self.store.get(operation_id)
            target = next(item for item in operation["targets"] if item["node_id"] == node_id)
            initial = target["state"]
            payload = {"controller_id": self.controller, "job_id": target["job_id"]}
            check = None
            try:
                if initial == "queued":
                    def check():
                        self.check(operation["actor"], "jobs:execute", [node_id])
                    check()
                    job = copy.deepcopy(operation["request"]["job"])
                    job["gpu_reservations"] = {node_id: job["gpu_reservations"][node_id]} if node_id in job["gpu_reservations"] else {}
                    payload.update(action="job.submit", job=job, node_id=node_id)
                    self.update(operation_id, node_id, {"state": "dispatching"})
                elif initial == "cancel_requested" and target.get("cancel_actor"):
                    def check():
                        self.check(target["cancel_actor"], "jobs:cancel", [node_id])
                    check()
                    payload.update(action="job.cancel", force=target["cancel_force"])
                else:
                    payload.update(action="job.status")
                response = await self.service.ssh.job(target["node"], payload, check=check)
                if response.get("job_id") != target["job_id"] or response.get("state") not in STATES - {"queued", "dispatching"}:
                    raise Failure("invalid_job_state", "The node returned an invalid job state.", 502)
                values = {key: response[key] for key in ("state", "result", "effective_limits", "session_lifetime", "reservations", "error") if key in response}
                latest = next(item for item in self.store.get(operation_id)["targets"] if item["node_id"] == node_id)
                if latest["state"] == "cancel_requested" and response["state"] not in TERMINAL and payload["action"] != "job.cancel":
                    values["state"] = "cancel_requested"
                self.update(operation_id, node_id, values)
                self.failures.pop(target["job_id"], None)
                if response["state"] in TERMINAL:
                    self.service.store.audit("job.result", target["job_id"], response["state"], operation["actor"])
            except Failure as exc:
                state = "failed" if initial == "queued" and (exc.status in (401, 403) or exc.code == "job_refused") else "unknown"
                self.update(operation_id, node_id, {"state": state, "error": exc.message})
                failures = min(self.failures.get(target["job_id"], 0) + 1, 5)
                self.failures[target["job_id"]] = failures
                self.retry[target["job_id"]] = time.monotonic() + min(30, 2**failures)

    async def cancel(self, operation_id: str, nodes: list[str], force: bool, actor: str):
        self.service.live()
        self.check(actor, "jobs:cancel", nodes)
        operation = self.store.get(operation_id)
        if not set(nodes).issubset(target["node_id"] for target in operation["targets"]):
            raise Failure("invalid_nodes", "Select machines in this operation.")
        for target in operation["targets"]:
            if target["node_id"] in nodes and target["state"] not in TERMINAL:
                if target["state"] == "queued":
                    target.update(state="cancelled", result={"reason": "cancelled_before_dispatch", "exit_code": None,
                                  "signal": None, "stdout_bytes": 0, "stderr_bytes": 0, "dropped_bytes": 0,
                                  "finished_at": time.time()})
                else:
                    target.update(state="cancel_requested", cancel_actor=actor, cancel_force=force)
        self.store.save(operation)
        self.service.store.audit("job.cancel", operation_id, "requested", actor)
        return operation

    async def logs(self, operation_id: str, node_id: str, stream: str, offset: int, limit: int, actor: str):
        operation = self.store.get(operation_id)
        target = next((item for item in operation["targets"] if item["node_id"] == node_id), None)
        if target is None:
            raise Failure("not_found", "The job target was not found.", 404)
        def check():
            self.check(actor, "jobs:logs", [node_id])
        if self.workers.locked():
            raise Failure("capacity", "The job connection queue is full. Retry the log request.", 429)
        async with self.workers:
            check()
            return await self.service.ssh.job(target["node"], {"action": "job.logs", "controller_id": self.controller,
                                               "job_id": target["job_id"], "stream": stream, "offset": offset, "limit": limit}, check=check)

    async def poll(self):
        if self.service.settings.demo:
            return
        while True:
            try:
                for operation in self.store.all():
                    for target in operation["targets"]:
                        job_id = target["job_id"]
                        if target["state"] in TERMINAL or job_id in self.inflight or self.retry.get(job_id, 0) > time.monotonic():
                            continue
                        self.inflight.add(job_id)
                        task = asyncio.create_task(self.work(operation["id"], target["node_id"], job_id))
                        self.tasks.add(task)
                        task.add_done_callback(self.tasks.discard)
                self.failed = False
            except sqlite3.Error:
                self.failed = True
            await asyncio.sleep(1)

    async def work(self, operation_id, node_id, job_id):
        try:
            await self.reconcile(operation_id, node_id)
        except sqlite3.Error:
            self.failed = True
        finally:
            self.inflight.discard(job_id)

    async def close(self):
        for task in self.tasks:
            task.cancel()
        with suppress(asyncio.CancelledError):
            await asyncio.gather(*self.tasks, return_exceptions=True)
