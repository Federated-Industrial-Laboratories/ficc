# SPDX-License-Identifier: Apache-2.0
"""Durable, explicitly resumed provider uploads bound to one immutable dataset."""

import asyncio
import time

from . import source_capabilities as capabilities
from . import source_runtime
from .errors import Failure
from .file_store import key_check
from .source_schema import CreateUpload, UploadOperation


class Uploads:
    def __init__(self, sources):
        self.sources, self.service, self.store = sources, sources.service, sources.store

    def get(self, identity, actor):
        value = self.store.get("source_uploads", identity)
        self.sources.current(actor, "write").require_record(value)
        self.sources.connection(value["connection_id"], actor, "write")
        return value

    def source(self, upload, actor):
        dataset = self.service.datasets.get(upload["dataset_id"], actor)
        self.service.datasets.safety.require(dataset)
        if dataset["manifest_digest"] != upload["manifest_digest"]:
            raise Failure("source_changed", "The upload dataset manifest changed.", 409)
        value = dataset["files"][upload["file_index"]]
        if (value["sha256"], value["size"]) != (upload["sha256"], upload["size"]):
            raise Failure("source_changed", "The upload source differs from the retained immutable version.", 409)
        return value

    async def begin(self, connection_id, body, key, actor):
        self.service.live()
        body = CreateUpload.model_validate(body).model_dump()
        key_check(key)
        connection = self.sources.connection(connection_id, actor, "write")
        module, _ = capabilities.provider(connection["provider"])
        if not module.METADATA.get("objects"):
            raise Failure("object_unsupported", "This provider does not expose multipart object storage.", 409)
        current = self.sources.current(actor, "write")
        digest = capabilities.parameter_digest({"connection_id": connection_id, **body})
        async with self.sources.admission:
            existing = self.store.existing("source_uploads", current, key, digest)
            if existing:
                return self.get(existing["id"], actor)
            if len(self.sources.tasks) >= self.sources.limits()["workers"]:
                raise Failure("capacity", "Wait for an active data operation to finish.", 429)
            dataset = await self.service.datasets.inputs(body["dataset_id"], actor)
            if body["file_index"] >= len(dataset["files"]):
                raise Failure("not_found", "The dataset file was not found.", 404)
            source = dataset["files"][body["file_index"]]
            capabilities.local(self.service, source, actor)
            current = self.sources.current(actor, "write")
            value = {**self.sources.owner(current), **body, "connection_id": connection_id,
                "manifest_digest": dataset["manifest_digest"], "sha256": source["sha256"], "size": source["size"],
                "state": "creating", "provider_upload_id": None, "part_bytes": None, "parts": None, "last_run_id": None}
            self.store.insert("source_uploads", value, key, digest)
            await self.admit(value, {"operation": "begin"}, "upload-begin-" + value["id"], actor)
            return self.get(value["id"], actor)

    async def operate(self, identity, body, key, actor):
        self.service.live()
        body = UploadOperation.model_validate(body).model_dump()
        async with self.sources.admission:
            value = self.get(identity, actor)
            if not value["provider_upload_id"]:
                raise Failure("upload_unknown", "The upload creation response was lost. Inspect provider-side uploads; creation will not be replayed.", 409)
            if value["state"] in {"completed", "aborted"} and body["operation"] not in {"status", "reconcile"}:
                raise Failure("upload_finished", "This upload already has a terminal receipt.", 409)
            if body["operation"] == "part" and body["part_number"] is None:
                raise Failure("part_required", "Select the part number to upload.")
            if value["state"] == "unknown" and body["operation"] not in {"status", "reconcile", "abort"}:
                raise Failure("upload_unknown", "Check the retained parts or reconcile publication before further writes.", 409)
            return await self.admit(value, body, key, actor)

    async def admit(self, upload, body, key, actor):
        key_check(key)
        principal = self.sources.current(actor, "write")
        digest = capabilities.parameter_digest({"upload_id": upload["id"], **body})
        previous = self.store.existing("source_runs", principal, key, digest)
        if previous:
            return self.sources.view("source_runs", previous)
        if len(self.sources.tasks) >= self.sources.limits()["workers"] or any(
            self.store.get("source_runs", identity).get("upload_id") == upload["id"] for identity in self.sources.tasks):
            raise Failure("capacity", "Wait for the current data or upload operation to finish.", 429)
        value = {**self.sources.owner(principal), "actor": actor, "connection_id": upload["connection_id"], "upload_id": upload["id"],
            "action": "write", "operation": body["operation"], "state": "queued", "rows": 0, "bytes": 0, "error": None,
            "dataset_id": upload["dataset_id"], "manifest_digest": upload["manifest_digest"]}
        self.store.insert("source_runs", value, key, digest)
        upload["last_run_id"] = value["id"]
        self.store.save("source_uploads", upload)
        self.sources.tasks[value["id"]] = asyncio.create_task(self.run(value, upload, body, actor))
        return self.sources.view("source_runs", value)

    async def run(self, value, upload, body, actor):
        receipt = None
        connection = None

        def check():
            current = self.sources.connection(upload["connection_id"], actor, "write")
            assert connection is not None
            if current["revision"] != connection["revision"]:
                raise Failure("source_changed", "The source approval changed.", 409)
            self.source(upload, actor)

        async def receive(event):
            nonlocal receipt
            if event["kind"] == "committing":
                value["state"] = "committing"
                self.store.save("source_runs", value)
            elif event["kind"] == "receipt":
                receipt = event
            else:
                raise Failure("stream_protocol", "The object provider returned an unexpected frame.", 502)

        try:
            async with self.sources.workers:
                connection = self.sources.connection(upload["connection_id"], actor, "write")
                check()
                if body["operation"] in {"begin", "part", "complete"}:
                    await self.service.audit_delivery.require("source.object." + body["operation"], value["id"],
                                                              self.sources.current(actor, "write"))
                    check()
                request = {**body, **{key: upload[key] for key in ("key", "size", "sha256", "manifest_digest", "part_bytes")},
                           "upload_id": upload["provider_upload_id"]}
                packet = await capabilities.packet(self.service, connection, actor, "object", request, write=True)
                if body["operation"] in {"part", "complete"}:
                    packet["source"] = capabilities.local(self.service, self.source(upload, actor), actor)
                value["state"] = "running"
                self.store.save("source_runs", value)
                with self.store.part_receipts(upload) as receipts:
                    packet["part_receipts"] = receipts
                    await source_runtime.execute(packet, self.sources.limits(), check, receive)
                if receipt is None:
                    raise Failure("upload_unknown", "The provider did not return an upload receipt.", 502)
                value["receipt"] = receipt
                outcome = receipt["outcome"]
                if outcome == "created":
                    upload.update(provider_upload_id=receipt["upload_id"], part_bytes=receipt["part_bytes"], parts=receipt["parts"], state="uploading")
                elif outcome in {"completed", "aborted", "unknown"}:
                    upload["state"] = outcome
                else:
                    upload["state"] = "uploading"
                upload["receipt"] = receipt
                value["state"] = "unknown" if outcome == "unknown" else "completed"
        except BaseException as exc:
            unknown = value["state"] in {"running", "committing"} and body["operation"] not in {"status", "reconcile"}
            value["state"] = "unknown" if unknown else "cancelled" if isinstance(exc, asyncio.CancelledError) else "failed"
            if unknown:
                upload["state"] = "unknown"
            elif body["operation"] == "begin":
                upload["state"] = "aborted"
            value["error"] = {"code": exc.code, "message": exc.message} if isinstance(exc, Failure) else {
                "code": "upload_interrupted", "message": "The upload stopped. Check retained parts or reconcile publication; uncertain writes are never replayed."}
        finally:
            value["finished_at"] = time.time()
            self.store.save("source_runs", value)
            self.store.save("source_uploads", upload)
            self.sources.audit("source.object", value, actor, value["state"])
            self.sources.tasks.pop(value["id"], None)
