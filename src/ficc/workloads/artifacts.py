# SPDX-License-Identifier: Apache-2.0
"""Publish fenced workload outputs through registered-file transfers and dataset manifests."""

import asyncio
import base64
import copy
import hashlib
from typing import Annotated

from ficc_node.file_access import CHUNK, encode, transfer_name
from pydantic import Field

from ..dataset_schema import DataSchema
from ..errors import Failure
from ..execution.spec import Count, Revision, digest
from ..file_schema import Entry
from ..file_store import key_check
from ..schema import Model
from .commands import fence
from .schema import TERMINAL

Object = Annotated[str, Field(pattern=r"^(stdout|stderr|output:[a-z][a-z0-9_.-]{0,79})$")]


class Dataset(Model):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    format: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{0,31}$")] = "binary"
    data_schema: DataSchema = Field(alias="schema")
    description: Annotated[str, Field(max_length=2048)] = ""


class Publication(Model):
    revision: Revision
    object: Object
    destination: Entry
    name: Annotated[str, Field(min_length=1, max_length=255)]
    dataset: Dataset | None = None


class Range(Model):
    object: Object
    offset: Count
    length: Annotated[int, Field(ge=1, le=CHUNK)]


class Publications:
    def __init__(self, queue):
        self.queue, self.service = queue, queue.service
        self.admission = asyncio.Lock()

    @property
    def transfers(self):
        return self.service.transfers

    def check(self, actor, source, *, retained=True):
        current = self.queue.actor(self.service.auth.current(actor), "jobs:logs")
        if current.project_id != source["project_id"]:
            raise Failure("not_found", "The output publication was not found in this project.", 404)
        if not retained:
            return current
        job = self.queue.owned(source["job_id"], current, "jobs:logs")
        if job.request.dataset is not None:
            dataset = self.service.datasets.get(job.request.dataset.id, current.id)
            self.service.datasets.safety.require(dataset)
        if job.current_attempt != source["attempt_id"]:
            raise Failure("attempt_changed", "The publication no longer names the current workload attempt.", 409)
        attempt = self.queue.records.attempt(source["attempt_id"])
        if (fence(attempt) != {key: source[key] for key in ("attempt_id", "generation", "plan_digest")}
                or attempt.node_id != source["node_id"]):
            raise Failure("attempt_changed", "The publication attempt binding changed.", 409)
        if source["object"] not in {"stdout", "stderr", *("output:" + item.name for item in attempt.plan.job.outputs)}:
            raise Failure("output_unavailable", "Select a declared workload output or log stream.", 409)
        if (attempt.state not in TERMINAL | {"unknown"} or not attempt.observed
                or not attempt.observed.cleanup_confirmed):
            raise Failure("output_unavailable", "Publication requires retained output with confirmed workload cleanup.", 409)
        return current

    async def read(self, source, actor, offset, length):
        while True:
            current = self.check(actor, source)
            try:
                result = await self.queue.collect(source["job_id"], [Range(object=source["object"], offset=offset, length=length)], current)
                break
            except Failure as exc:
                if exc.code != "executor_busy":
                    raise
                await asyncio.sleep(0.05)
        row = result["results"][0]
        if (result["attempt_id"] != source["attempt_id"] or not row["complete"]
                or row["identity"] != source["output_identity"] or row["total_bytes"] != source["output_bytes"]):
            raise Failure("source_changed", "The retained workload output changed. Do not append it to this publication.", 409)
        data = base64.b64decode(row["data"], validate=True)
        if len(data) != min(length, source["output_bytes"] - offset):
            raise Failure("executor_response", "The executor returned an incomplete publication range.", 502)
        self.check(actor, source)
        return {"offset": offset, "next_offset": offset + len(data), "sha256": hashlib.sha256(data).hexdigest()}, data

    async def source(self, operation, item, action, **values):
        source, actor = item["workload_source"], operation["actor"]
        self.service.auth.record(actor, operation)
        if action == "file.read":
            return await self.read(source, actor, values["offset"], values["limit"])
        if action != "file.hash":
            raise Failure("artifact_action", "The publication source supports only bounded reads and hashing.", 409)
        # A complete digest can be reused only while the exact closed file identity still matches.
        if item.get("sha256"):
            await self.read(source, actor, 0, 1)
            return {"sha256": item["sha256"]}, b""
        value = hashlib.sha256()
        item.update(phase="hashing", hashed_bytes=0)
        self.transfers.save_item(operation, item)
        if source["output_bytes"] == 0:
            await self.read(source, actor, 0, 1)
        for offset in range(0, source["output_bytes"], CHUNK):
            self.transfers.check(actor, item, operation["kind"])
            _header, data = await self.read(source, actor, offset, CHUNK)
            value.update(data)
            item["hashed_bytes"] = offset + len(data)
            self.transfers.save_item(operation, item)
        item["phase"] = "copying"
        self.transfers.save_item(operation, item)
        return {"sha256": value.hexdigest()}, b""

    async def publish(self, identity, body, key, actor):
        self.service.live()
        key_check(key)
        body = Publication.model_validate(body).model_dump(by_alias=True)
        requested = digest({"job_id": identity, **body})
        async with self.admission:
            job = self.queue.owned(identity, actor, "jobs:logs")
            actor = self.queue.actor(actor, "files:write")
            actor.require("files:read")
            previous = self.transfers.store.existing(actor.id, key)
            if previous:
                binding = previous.get("workload_publication", {})
                if binding.get("job_id") != identity or binding.get("digest") != requested:
                    raise Failure("idempotency_conflict", "This key belongs to another publication request.", 409)
                return self.view(previous, actor.id)
            if job.revision != body["revision"] or job.current_attempt is None:
                raise Failure("attempt_changed", "Reload the workload before publishing its output.", 409)
            attempt = self.queue.records.attempt(job.current_attempt)
            source = {"kind": "workload", "job_id": job.id, "project_id": job.project_id, **fence(attempt),
                      "node_id": attempt.node_id, "object": body["object"],
                      "input_dataset": job.request.dataset.model_dump() if job.request.dataset else None}
            self.check(actor.id, source)
            observed = await self.queue.collect(identity, [Range(object=body["object"], offset=0, length=1)], actor)
            row = observed["results"][0]
            if observed["attempt_id"] != attempt.id or not row["complete"]:
                raise Failure("output_unavailable", "Wait for complete retained output before publication.", 409)
            source.update(output_identity=row["identity"], output_bytes=row["total_bytes"])
            if body["dataset"] is not None:
                self.service.datasets.artifacts.available()
                if source["input_dataset"]:
                    self.service.datasets.get(source["input_dataset"]["id"], actor.id)
            # Admission and output release use the same contributor lock.
            async with self.queue.runner.lock(attempt.node_id):
                self.check(actor.id, source)
                preview = await self.transfers.preview({"kind": "upload", "sources": [{"name": body["name"], "size": row["total_bytes"]}],
                    "destination": body["destination"], "overwrite": False}, actor.id)
                saved = self.transfers.previews[preview["preview_id"]]
                if saved["conflicts"]:
                    raise Failure("destination_conflict", "The destination name already exists. Select a new filename.", 409)
                saved.update(kind="copy", workload_publication={"job_id": identity, "digest": requested})
                item = saved["items"][0]
                item.update(workload_source=source, dataset_request=body["dataset"], dataset=None,
                            dataset_error=None, dataset_cancelled=False, phase="queued", hashed_bytes=0)
                item["spec"]["source_identity"] = copy.deepcopy(source)
                operation = await self.transfers.submit(preview["preview_id"], key, actor.id)
            self.queue.audit("workload.publish", identity, actor)
            return self.view(operation, actor.id)

    def selected(self, identity, operation_id, actor):
        self.queue.owned(identity, self.service.auth.current(actor), "jobs:logs")
        operation = self.transfers.store.get(operation_id)
        self.service.auth.record(actor, operation)
        if operation.get("workload_publication", {}).get("job_id") != identity:
            raise Failure("not_found", "The output publication was not found.", 404)
        return operation

    def view(self, operation, actor):
        item = operation["items"][0]
        self.check(actor, item["workload_source"], retained=False)
        transfer = self.transfers.view(operation, actor)
        phase = "complete" if item["state"] == "succeeded" and not item.get("dataset_request") else item.get("phase", "queued")
        return {"transfer": transfer, "source": item["workload_source"], "phase": phase,
                "hashed_bytes": item.get("hashed_bytes", 0), "dataset": item.get("dataset"),
                "dataset_requested": item.get("dataset_request") is not None,
                "dataset_cancelled": item.get("dataset_cancelled", False), "dataset_error": item.get("dataset_error")}

    def all(self, identity, actor, before=None):
        current = self.service.auth.current(actor)
        self.queue.owned(identity, current, "jobs:logs")
        found, values, cursor = before is None, [], None
        for operation in self.transfers.store.iterate(project_id=current.project_id):
            if not found:
                found = operation["id"] == before
                continue
            if operation.get("workload_publication", {}).get("job_id") != identity:
                continue
            try:
                value = self.view(operation, actor)
            except Failure as exc:
                if exc.status in {403, 404}:
                    continue
                raise
            values.append(value)
            if len(values) == 50:
                cursor = operation["id"]
                break
        return {"publications": values, "next_cursor": cursor}

    def require_releasable(self, identity, *, removing=False):
        for operation in self.transfers.store.iterate():
            if operation.get("workload_publication", {}).get("job_id") != identity:
                continue
            for item in operation["items"]:
                pending_dataset = item.get("dataset_request") and not item.get("dataset") and not item.get("dataset_cancelled")
                if item["state"] not in {"succeeded", "cancelled"} or removing and pending_dataset and item["state"] != "cancelled":
                    raise Failure("output_publication_active", "Finish or cancel the output publication before releasing or removing this workload.", 409)

    async def complete(self, operation_id, item_id, actor=None):
        async with self.transfers.locks.setdefault(item_id, asyncio.Lock()):
            operation = self.transfers.store.get(operation_id)
            item = next(value for value in operation["items"] if value["id"] == item_id)
            if (item["state"] != "succeeded" or not item.get("dataset_request")
                    or item.get("dataset") or item.get("dataset_cancelled")):
                return
            actor = actor or item.get("actor", operation["actor"])
            try:
                current = self.check(actor, item["workload_source"], retained=False)
                if current.subject_id != operation["subject_id"]:
                    raise Failure("publication_owner", "The publication requester must complete dataset registration.", 403)
                self.transfers.check(actor, item, operation["kind"])
                artifact = item.get("artifact")
                if not artifact or not artifact["verified"] or artifact["digest"] != item["sha256"] or artifact["size"] != item["size"]:
                    raise Failure("artifact_unverified", "Reconcile the committed file before registering its dataset.", 409)
                root = item["destination"]["root"]
                reference = {"parts": [*item["spec"]["parent"]["parts"], encode(transfer_name(item["spec"]))],
                             "identity": artifact["identity"], "parent": item["spec"]["parent"]["identity"]}
                await self.service.files.stat(root, reference, actor)
                source = item["workload_source"]
                inputs = [source["input_dataset"]["id"]] if source["input_dataset"] else []
                origin = {**source, "transfer_id": operation_id, "item_id": item_id}
                body = {**item["dataset_request"], "sources": [{"root_id": root["id"], "entry_id": self.service.files.refs.issue(root, reference)}],
                        "provenance": {"description": "Verified retained workload output.", "input_dataset_ids": inputs}}
                item.update(phase="registering_dataset", dataset_error=None)
                self.transfers.save_item(operation, item)
                result = await self.service.datasets.create(body, "workload-output:" + operation_id, actor, origin=origin)
                item["dataset"] = {key: result[key] for key in ("id", "name", "manifest_digest")}
                if hasattr(self.service, "inspections"):
                    await self.service.inspections.publication(result, actor)
                if (len(result["files"]) != 1 or result["files"][0]["sha256"] != item["sha256"]
                        or result["files"][0]["size"] != item["size"]):
                    raise Failure("artifact_changed", "The dataset source differs from the committed output.", 409)
                item.update(dataset={key: result[key] for key in ("id", "name", "manifest_digest")}, phase="complete", dataset_error=None)
            except asyncio.CancelledError:
                item.update(dataset_error={"code": "interrupted", "message": "File publication succeeded; dataset registration was interrupted."})
                self.transfers.save_item(operation, item)
                raise
            except Exception as exc:
                item.update(dataset_error={"code": exc.code if isinstance(exc, Failure) else "dataset_publication_failed",
                    "message": exc.message if isinstance(exc, Failure) else "File publication succeeded; dataset registration requires recovery."})
            self.transfers.save_item(operation, item)

    async def change(self, identity, operation_id, actor, *, resume=False, discard=False):
        operation = self.selected(identity, operation_id, actor)
        item = operation["items"][0]
        if item["state"] == "succeeded":
            if resume:
                await self.complete(operation_id, item["id"], actor)
            elif item.get("dataset_request") and not item.get("dataset"):
                current = self.service.auth.current(actor)
                current.require("files:write")
                task = self.transfers.tasks.get(item["id"])
                if task:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                async with self.transfers.locks.setdefault(item["id"], asyncio.Lock()):
                    operation = self.selected(identity, operation_id, actor)
                    item = operation["items"][0]
                    if not item.get("dataset"):
                        item.update(dataset_cancelled=True, dataset_error=None)
                    self.transfers.save_item(operation, item)
        else:
            await self.transfers.change(operation_id, [item["id"]], actor, resume=resume, discard=discard)
        return self.view(self.transfers.store.get(operation_id), actor)
