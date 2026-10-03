# SPDX-License-Identifier: Apache-2.0
"""Optional local inspection with durable coverage and current safety enforcement."""

import asyncio
import hashlib
import os
import secrets
import time
from pathlib import Path

from ficc_node.file_access import parts

from . import inspection_runtime
from .dataset_store import encoded
from .errors import Failure
from .file_store import key_check
from .inspection_schema import InspectionConfig
from .inspection_sdk import InspectionError, load, result
from .inspection_store import InspectionStore
from .source_capabilities import local

PRIORITY = {"no_detection": 0, "incomplete": 1, "unavailable": 2, "error": 3, "detected": 4}


class Inspections:
    def __init__(self, service):
        self.service, self.store = service, InspectionStore(service.store)
        self.tasks: dict[str, asyncio.Task] = {}
        self.admission = asyncio.Lock()
        self.store.recover()

    def config(self):
        return self.service.datasets.safety.config()

    def current(self, identity, actor):
        value = self.service.datasets.get(identity, actor)
        self.service.datasets.artifacts.current(actor).require("files:write")
        return value

    def settings(self, actor):
        current = self.service.datasets.artifacts.current(actor)
        current.require("files:read")
        config = self.config()
        available, installed = False, None
        if config["provider"]:
            try:
                module, installed = load(config["provider"])
                inspection_runtime.approved_assets(self.service, module, config["configuration"])
                available = installed == self.service.store.get_setting("inspection_approval", None)
            except (InspectionError, Failure, ImportError, OSError, ValueError):
                pass
        return {"configured": config["provider"] is not None, "available": available, "provider": config["provider"],
                "installed": installed, "configuration": config if current.local_owner else None,
                "can_manage": current.local_owner and current.node_ids is None and current.root_ids is None and current.permits("files:write")}

    def configure(self, body, actor):
        self.service.live()
        current = self.service.datasets.safety.owner(actor)
        value = InspectionConfig.model_validate(body).model_dump()
        installed = None
        if value["provider"]:
            try:
                module, installed = load(value["provider"])
                value["configuration"] = module.configuration(value["configuration"])
                inspection_runtime.approved_assets(self.service, module, value["configuration"])
            except (InspectionError, ImportError, OSError, ValueError):
                raise Failure("scanner_unavailable", "Install and approve the local scanner engine and signature assets first.", 409) from None
        if self.tasks:
            raise Failure("inspection_busy", "Wait for active inspections before changing scanner configuration.", 409)
        with self.service.store.lock, self.service.store.db:
            self.service.store.set_setting("inspection_config", value)
            self.service.store.set_setting("inspection_approval", installed)
            self.service.store.audit("inspection.configure", value["provider"] or "disabled", "approved", current.id,
                                     subject_id=current.subject_id, project_id=current.project_id)
        return self.settings(actor)

    async def on_create(self, value, actor):
        safety = self.service.datasets.safety.effective(value)
        if safety["inspection_required"] or self.config()["scan_on_create"]:
            try:
                await self.submit(value["id"], "dataset-inspection-" + value["id"], actor)
            except Failure as exc:
                if exc.code != "inspection_capacity":
                    raise
                # The durable dataset stays blocked if inspection is required.
                # A busy optional stage must not hide a successful registration.

    async def publication(self, value, actor):
        """Wait for an import's admitted local scan before a required publication."""
        safety = self.service.datasets.safety.effective(value)
        if safety["inspection_required"] and safety["inspection"]:
            task = self.tasks.get(safety["inspection"]["id"])
            if task:
                await asyncio.shield(task)
        return self.service.datasets.safety.require(self.service.datasets.get(value["id"], actor))

    async def submit(self, identity, key, actor):
        self.service.live()
        key_check(key)
        dataset = self.current(identity, actor)
        principal = self.service.datasets.artifacts.current(actor)
        config = self.config()
        digest = hashlib.sha256(encoded({"dataset": identity, "manifest": dataset["manifest_digest"], "config": config})).hexdigest()
        async with self.admission:
            with self.service.store.lock, self.service.store.db:
                previous = self.service.store.db.execute("SELECT id,digest FROM inspection_runs WHERE subject_id=:p0 AND project_id=:p1 AND key=:p2",
                    (principal.subject_id, principal.project_id, key)).fetchone()
                if previous:
                    if previous[1] != digest:
                        raise Failure("idempotency_conflict", "This key belongs to another inspection request.", 409)
                    return self.get(previous[0], actor)
                if len(self.tasks) >= config["workers"] or any(self.store.run(identity)["dataset_id"] == dataset["id"] for identity in self.tasks):
                    raise Failure("inspection_capacity", "Wait for an active inspection to finish.", 429)
                value = {"id": secrets.token_hex(16), "subject_id": principal.subject_id, "project_id": principal.project_id,
                    "dataset_id": dataset["id"], "manifest_digest": dataset["manifest_digest"], "state": "queued", "outcome": "incomplete",
                    "config_digest": hashlib.sha256(encoded(config)).hexdigest(), "provider": config["provider"], "created_at": time.time(),
                    "completed_files": 0, "total_files": len(dataset["files"]), "reason": "pending"}
                self.service.store.db.execute("INSERT INTO inspection_runs VALUES (:p0,:p1,:p2,:p3,:p4,:p5,:p6)",
                    (value["id"], principal.subject_id, principal.project_id, identity, key, digest, encoded(value).decode()))
                policy = self.store.policy(identity)
                policy["latest_run"] = value["id"]
                self.store.policy_save(policy)
                self.service.store.audit("inspection.start", value["id"], "queued", principal.id,
                    subject_id=principal.subject_id, project_id=principal.project_id)
            self.tasks[value["id"]] = asyncio.create_task(self.run(value, dataset, config, actor))
        return self.get(value["id"], actor)

    def get(self, identity, actor):
        value = self.store.run(identity)
        self.service.datasets.get(value["dataset_id"], actor)
        self.service.datasets.artifacts.current(actor).require_record(value)
        return value

    def files(self, identity, actor, after=-1):
        self.get(identity, actor)
        return self.store.files(identity, after)

    async def run(self, value, dataset, config, actor):
        outcomes = []
        def check():
            current = self.current(dataset["id"], actor)
            if current["manifest_digest"] != value["manifest_digest"] or self.config() != config:
                raise Failure("inspection_changed", "The inspection authority or configuration changed.", 409)

        try:
            value.update(state="running", reason=None)
            self.store.save(value)
            if config["provider"] is None:
                raise Failure("scanner_unavailable", "No local inspection provider is configured.", 409)
            module, installed = load(config["provider"])
            if installed != self.service.store.get_setting("inspection_approval", None):
                raise Failure("scanner_unavailable", "The configured scanner package is absent or changed.", 409)
            assets = inspection_runtime.approved_assets(self.service, module, config["configuration"])
            for number, source in enumerate(dataset["files"]):
                check()
                root = self.service.files.store.root(source["root_id"])
                if root.get("node_id") is not None:
                    receipt = {"outcome": "unavailable", "coverage": {"reasons": ["remote_location_unsupported"], "relayed": False},
                               "engine": {}, "signatures": {}, "sha256": source["sha256"], "bytes": source["size"]}
                else:
                    capability = local(self.service, source, actor)
                    receipt = None

                    async def receive(event):
                        nonlocal receipt
                        if event.get("kind") != "receipt":
                            raise Failure("inspection_protocol", "The scanner returned an unexpected event.", 502)
                        receipt = result({key: item for key, item in event.items() if key != "kind"})

                    packet = {"provider": config["provider"], "installed": installed, "configuration": config["configuration"], "assets": assets,
                        "private_path": str(self.service.settings.state_dir),
                        "file_path": str(Path(capability["root"]["path"]) / os.fsdecode(b"/".join(parts(capability["reference"])))),
                        "source": {"identity": source["reference"]["identity"], "sha256": source["sha256"], "size": source["size"]}}
                    await inspection_runtime.execute(packet, config, check, receive)
                    check()
                    if receipt is None or receipt["sha256"] != source["sha256"] or receipt["bytes"] != source["size"]:
                        raise Failure("inspection_binding", "The scanner receipt does not match the immutable file.", 409)
                    # Verify the registered path again, not only the inode pinned in the child.
                    await self.service.datasets.artifacts.verify(source, actor)
                check()
                assert receipt is not None
                outcomes.append(receipt["outcome"])
                with self.service.store.lock, self.service.store.db:
                    self.service.store.db.execute("INSERT INTO inspection_files VALUES (:p0,:p1,:p2)",
                        (value["id"], number, encoded({"file_index": number, **receipt}).decode()))
                    if receipt["outcome"] == "detected":
                        policy = self.store.policy(dataset["id"])
                        policy.update(quarantined=True, revision=policy["revision"] + 1, exemption=None)
                        self.store.policy_save(policy)
                    value["completed_files"] = number + 1
                    self.store.save(value)
            value["outcome"] = max(outcomes, key=lambda item: PRIORITY[item])
        except BaseException as exc:
            if isinstance(exc, asyncio.CancelledError):
                value.update(outcome="incomplete", reason="cancelled")
            elif isinstance(exc, (InspectionError, Failure)):
                unavailable = exc.code in {"provider_unavailable", "provider_version", "scanner_unavailable", "scanner_assets", "scanner_layout"}
                value.update(outcome="unavailable" if unavailable else "error", reason=exc.code)
            elif isinstance(exc, OSError):
                value.update(outcome="unavailable", reason="scanner_assets_unavailable")
            elif isinstance(exc, TimeoutError):
                value.update(outcome="incomplete", reason="worker_deadline")
            else:
                value.update(outcome="error", reason="worker_failed")
        finally:
            if "detected" in outcomes:
                value["outcome"] = "detected"
            value.update(state="completed", finished_at=time.time())
            self.store.save(value)
            self.service.store.audit("inspection.result", value["id"], value["outcome"], actor,
                subject_id=value["subject_id"], project_id=value["project_id"])
            self.tasks.pop(value["id"], None)

    async def cancel(self, identity, actor):
        value = self.get(identity, actor)
        self.current(value["dataset_id"], actor)
        task = self.tasks.get(identity)
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            if task.cancelled():
                value.update(state="completed", outcome="incomplete", reason="cancelled", finished_at=time.time())
                self.store.save(value)
                self.tasks.pop(identity, None)
        return self.get(identity, actor)

    async def close(self):
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
