# SPDX-License-Identifier: Apache-2.0
"""Persistent services compose admitted contributor attempts and verified models."""
import asyncio
import secrets
import time

from ..errors import Failure
from ..workloads.schema import Submission
from .attached import Attached
from .gateway import Gateway
from .providers import Providers
from .records import Records
from .schema import Record


class Inference:
    def __init__(self, service):
        self.service = service
        self.records = Records(service.store, "inference_services")
        self.providers = Providers()
        self.gateway = Gateway(self)
        self.attached = Attached(self)
        self.ready = set()
        self.lock = asyncio.Lock()
        self.checking = {}
        self.probed = {}
        self.initialized = set()
        self.scoped_tokens = {credential: row["id"] for row in self.records.all() for credential in row.get("invoke_credentials", [])}

    def get(self, identity, actor, scope="inference:read"):
        current = self.service.auth.current(actor.id)
        current.require(scope)
        value = self.records.get(identity)
        current.require_record(value)
        if current.id in self.scoped_tokens and self.scoped_tokens[current.id] != identity:
            raise Failure("not_found", "This credential does not permit this inference service.", 404)
        if current.node_ids is not None or current.root_ids is not None:
            raise Failure("denied", "Inference services require a project credential without machine restrictions.", 403)
        return value

    def token(self, identity, actor, lifetime=3600):
        value = self.get(identity, actor, "inference:manage")
        actor = self.service.auth.current(actor.id)
        actor.require("tokens:manage")
        actor.require("inference:invoke")
        with self.service.store.lock, self.service.store.db:
            secret, principal = self.service.auth.issue("token", "Inference " + value["spec"]["alias"],
                ["inference:invoke"], lifetime=lifetime, subject_id=actor.subject_id, project_id=actor.project_id)
            value.setdefault("invoke_credentials", []).append(principal.id)
            value["revision"] += 1
            self.records.save(value)
            self.scoped_tokens[principal.id] = identity
        return {"id": principal.id, "token": secret, "expires_at": principal.expires_at,
                "endpoint": "/api/v1/inference/" + identity + "/v1"}

    def view(self, record):
        if record["spec"]["engine"] == "attached":
            try:
                capabilities = self.attached.profile(record["spec"], record["project_id"]).capabilities
            except Failure:
                capabilities = []
        else:
            capabilities = self.service.models.records.get(record["spec"]["model_id"])["manifest"]["capabilities"]
        return {**record, "capabilities": capabilities,
                "replicas": [self.service.workloads.view(self.service.workloads.records.get(identity)) for identity in record["workloads"]],
                "active_requests": self.gateway.active.get(record["id"], 0),
                "endpoint": "/api/v1/inference/" + record["id"] + "/v1"}

    def ready_attempts(self, record):
        queue = self.service.workloads
        values = []
        for identity in record["workloads"]:
            job = queue.records.get(identity)
            if job.current_attempt and job.state == "running" and job.current_attempt in self.ready:
                attempt = queue.records.attempt(job.current_attempt)
                if queue.runner.available(attempt.node_id):
                    values.append(attempt)
        return values

    def preview(self, spec, actor):
        current = self.service.auth.current(actor.id)
        current.require("inference:manage")
        if spec.engine == "attached":
            self.attached.profile(spec.model_dump(), current.project_id)
            return []
        model = self.service.models.bind(spec.model_id, current)
        inputs = self.service.models.references(model)
        adapter = self.providers.get(spec.engine)
        jobs = []
        for placement in spec.placements:
            self.service.workloads.authority.node(current.project_id, placement.node_id)
            observed = self.service.workloads.runner.live.get(placement.node_id)
            if not observed or observed[0].endpoint_version != 1:
                raise Failure("endpoint_upgrade_required", "Connect a contributor with inference endpoint support before deployment.", 409)
            job = adapter.job(spec, model, placement, inputs)
            if not job.limits.fits(observed[0].capacity.available):
                raise Failure("inference_capacity", "The selected placement exceeds currently available contributor resources.", 409)
            jobs.append(Submission(job=job, node_ids=[placement.node_id], model_revision=model["id"]))
        return jobs

    async def create(self, spec, actor):
        self.service.live()
        async with self.lock:
            jobs = self.preview(spec, actor)
            from ..execution.spec import digest
            await self.service.audit_delivery.require("inference.create", digest(spec.model_dump()), actor)
            actor = self.service.auth.current(actor.id)
            jobs = self.preview(spec, actor)
            if any(item["spec"]["alias"] == spec.alias for item in self.records.all(actor.project_id)):
                raise Failure("inference_alias", "This project already has a service with this alias.", 409)
            value = Record(id=secrets.token_hex(16), project_id=actor.project_id, subject_id=actor.subject_id, actor=actor.id,
                           spec=spec, generation=1, desired="running", state="pending", reason=None, workloads=[],
                           created_at=time.time(), revision=1).model_dump()
            # Hold one database transaction across all workload records; submit() may audit
            # asynchronously, so construct delegated records only after all preflight checks.
            queue = self.service.workloads
            if jobs and (queue.scheduler is None or queue.suspended()):
                raise Failure("scheduler_unavailable", "Configure and enable contributor workload scheduling first.", 409)
            delegations = [queue.authority.capture(actor, request) for request in jobs]
            with self.service.store.lock, self.service.store.db:
                for index, (request, delegation) in enumerate(zip(jobs, delegations, strict=True)):
                    queue.inputs.bind(request, delegation)
                    record = queue.records.submit(request, value["id"] + ":" + str(index), delegation)
                    value["workloads"].append(record.id)
                self.records.save(value)
                queue.audit("inference.create", value["id"], actor)
            return self.view(value)

    async def replace(self, identity, spec, revision, actor):
        async with self.lock:
            value = self.get(identity, actor, "inference:manage")
            if value["revision"] != revision or value["state"] != "stopped":
                raise Failure("service_running", "Stop and release the current replicas before changing their placements or model.", 409)
            jobs = self.preview(spec, actor)
            if any(item["id"] != identity and item["spec"]["alias"] == spec.alias for item in self.records.all(actor.project_id)):
                raise Failure("inference_alias", "Another service already has this alias.", 409)
            queue = self.service.workloads
            from ..execution.spec import digest
            await self.service.audit_delivery.require("inference.replace", digest(spec.model_dump()), actor)
            value = self.get(identity, actor, "inference:manage")
            if value["revision"] != revision or value["state"] != "stopped":
                raise Failure("revision_conflict", "Reload the stopped service before replacing it.", 409)
            actor = self.service.auth.current(actor.id)
            jobs = self.preview(spec, actor)
            with self.service.store.lock, self.service.store.db:
                delegations = [queue.authority.capture(actor, request) for request in jobs]
                for job_id in value["workloads"]:
                    old = queue.owned(job_id, actor, "jobs:cancel")
                    queue.records.remove(job_id, old.revision)
                value.update(spec=spec.model_dump(), generation=value["generation"] + 1, workloads=[],
                             desired="running", state="pending", reason=None, revision=value["revision"] + 1)
                for index, (request, delegation) in enumerate(zip(jobs, delegations, strict=True)):
                    queue.inputs.bind(request, delegation)
                    job = queue.records.submit(request, identity + ":" + str(value["generation"]) + ":" + str(index), delegation)
                    value["workloads"].append(job.id)
                self.records.save(value)
                queue.audit("inference.replace", identity, actor)
            return self.view(value)

    async def control(self, identity, operation, revision, actor, *, acknowledge_unknown=False):
        async with self.lock:
            value = self.get(identity, actor, "inference:manage")
            if value["revision"] != revision:
                raise Failure("revision_conflict", "Reload the service before changing its desired state.", 409)
            queue = self.service.workloads
            if acknowledge_unknown and operation != "start":
                raise Failure("inference_action", "Unknown outcomes can be acknowledged only when starting new attempts.", 422)
            if operation == "remove":
                if value["state"] != "stopped":
                    raise Failure("service_running", "Stop and release all service replicas before removal.", 409)
                for job_id in value["workloads"]:
                    job = queue.records.get(job_id)
                    queue.remove(job_id, job.revision, actor)
                for credential in value.get("invoke_credentials", []):
                    self.service.auth.revoke(credential)
                self.records.remove(identity)
                return {"id": identity, "removed": True}
            if operation == "start":
                if value["state"] != "stopped":
                    raise Failure("service_running", "Start requires all earlier replicas to be stopped and released.", 409)
                jobs = [queue.records.get(job_id) for job_id in value["workloads"]]
                if any(job.state == "unknown" for job in jobs) and not acknowledge_unknown:
                    raise Failure("inference_unknown_outcome", "An earlier replica has an unknown outcome. Acknowledge it explicitly to start new attempts; previous requests are not replayed.", 409)
                if any(job.current_attempt and queue.records.attempt(job.current_attempt).state != "released" for job in jobs):
                    raise Failure("workload_unresolved", "Starting new attempts requires confirmed release of every earlier replica.", 409)
                for job_id in value["workloads"]:
                    job = queue.records.get(job_id)
                    await queue.retry(job_id, job.revision, actor, acknowledge_unknown=acknowledge_unknown)
                value.update(desired="running", state="pending", generation=value["generation"] + 1, reason=None)
            elif operation in {"stop", "drain"}:
                value.update(desired="stopped" if operation == "stop" else "draining", state="draining")
                if operation == "stop":
                    for job_id in value["workloads"]:
                        job = queue.records.get(job_id)
                        queue.cancel(job_id, job.revision, actor)
            else:
                raise Failure("inference_action", "Choose start, stop, drain or remove.", 422)
            value["revision"] += 1
            self.records.save(value)
            return self.view(value)

    async def health(self, record, attempt):
        queue = self.service.workloads
        def check():
            queue.runner.authority(attempt)
        spec = record["spec"]
        if spec["engine"] == "ollama":
            await self.gateway.json(attempt, "/api/version", None, check, 10)
            model = self.service.models.records.get(spec["model_id"])
            if attempt.id not in self.initialized:
                for item in attempt.plan.job.inputs:
                    await self.gateway.json(attempt, "/api/blobs/" + item.digest, None, check, 600, input_object=item.id)
                files = {item["name"]: item["digest"] for item in model["manifest"]["files"]}
                await self.gateway.json(attempt, "/api/create", {"model": spec["alias"], "files": files, "stream": False}, check, 600)
                await self.gateway.json(attempt, "/api/chat", {"model": spec["alias"], "messages": [], "stream": False, "keep_alive": -1}, check, 600)
                self.initialized.add(attempt.id)
            result = await self.gateway.json(attempt, "/api/ps", None, check, 10)
            resident = [item for item in result.get("models", []) if item.get("name", "").split(":")[0] == spec["alias"]]
            if attempt.plan.job.limits.gpu_devices and not any(item.get("size_vram", 0) > 0 for item in resident):
                raise Failure("model_not_on_gpu", "Ollama did not load the selected model on an admitted GPU. Inspect the CUDA runtime and device libraries.", 409)
            if not resident:
                raise Failure("model_not_resident", "Ollama has not loaded the selected model.", 409)
        else:
            await self.gateway.json(attempt, "/health", None, check, 10)
            result = await self.gateway.json(attempt, "/v1/models", None, check, 10)
            if not any(item.get("id") == spec["alias"] for item in result.get("data", [])):
                raise Failure("model_identity", "The engine did not advertise the selected service model.", 409)
        self.ready.add(attempt.id)

    async def reconcile(self, value):
        if value["spec"]["engine"] != "attached":
            return await self.reconcile_managed(value)
        await self.attached.reconcile(value)
        current = self.records.get(value["id"])
        if current["revision"] == value["revision"] and current != value:
            value["revision"] += 1
            self.records.save(value)

    async def reconcile_managed(self, value):
        queue = self.service.workloads
        jobs = [queue.records.get(identity) for identity in value["workloads"]]
        if value["desired"] in {"stopped", "draining"}:
            if value["desired"] == "draining" and self.gateway.active.get(value["id"], 0):
                return
            released = True
            for job in jobs:
                if not job.cancelled:
                    queue.records.cancel(job.id, job.revision)
                if job.current_attempt:
                    attempt = queue.records.attempt(job.current_attempt)
                    self.ready.discard(attempt.id)
                    if attempt.state != "released":
                        released = False
                        if attempt.observed and attempt.observed.cleanup_confirmed:
                            async with queue.runner.lock(attempt.node_id):
                                snapshot = queue.runner.live.get(attempt.node_id)
                                if snapshot:
                                    await queue.commands.batch(attempt.node_id, snapshot[0], "release", [attempt])
            value.update(state="stopped" if released else "draining", desired="stopped")
        else:
            for job in jobs:
                identity = job.current_attempt
                if not identity:
                    continue
                task = self.checking.get(identity)
                if task is not None and task.done():
                    try:
                        task.result()
                    except (Failure, OSError, ValueError) as exc:
                        self.ready.discard(identity)
                        value["reason"] = exc.code if isinstance(exc, Failure) else "engine_unavailable"
                    self.probed[identity] = time.monotonic()
                    del self.checking[identity]
                    task = None
                if job.state != "running":
                    self.ready.discard(identity)
                    continue
                interval = 30 if identity in self.ready else 2
                if task is None and time.monotonic() - self.probed.get(identity, 0) > interval and len(self.checking) < 4:
                    self.checking[identity] = asyncio.create_task(self.health(value, queue.records.attempt(identity)))
            ready = len(self.ready_attempts(value))
            states = {job.state for job in jobs}
            value["state"] = ("ready" if ready == len(jobs) else "degraded" if ready else "unknown" if "unknown" in states
                              else "failed" if states & {"failed", "expired", "succeeded", "cancelled"} else "loading" if "running" in states
                              else "preparing" if states & {"preparing", "prepared", "starting"} else "pending")
            if value["state"] == "ready":
                value["reason"] = None
        current = self.records.get(value["id"])
        if current["revision"] == value["revision"] and current != value:
            value["revision"] += 1
            self.records.save(value)

    async def poll(self):
        try:
            while True:
                for value in self.records.all():
                    try:
                        await self.reconcile(value)
                    except (Failure, ValueError, OSError):
                        continue
                await asyncio.sleep(1)
        finally:
            await self.attached.close()
            for task in self.checking.values():
                task.cancel()
            await asyncio.gather(*self.checking.values(), return_exceptions=True)
