# SPDX-License-Identifier: Apache-2.0
"""Register dataset versions and reauthorize immutable source snapshots for jobs."""

import asyncio
import copy
import hashlib
import secrets
import time

from .artifacts import Artifacts
from .dataset_schema import CreateDataset
from .dataset_store import DatasetStore, encoded, seal
from .errors import Failure
from .file_store import key_check


class Datasets:
    def __init__(self, service):
        self.service = service
        self.artifacts = Artifacts(service)
        self.store = DatasetStore(service.store, service.files.refs.key)
        self.admission = asyncio.Lock()
        from .dataset_safety import DatasetSafety
        self.safety = DatasetSafety(service)

    def get(self, identity, actor):
        current = self.artifacts.current(actor)
        value = self.store.get(identity)
        current.require_record(value)
        current.require("files:read")
        for source in value["files"]:
            self.artifacts.capability(source, actor)
        return value

    def view(self, value):
        public = copy.deepcopy(value)
        public["files"] = [{name: item for name, item in source.items() if name != "reference"} for source in value["files"]]
        public["safety"] = self.safety.effective(value)
        return public

    def all(self, actor, before=None):
        current = self.artifacts.current(actor)
        current.require("files:read")
        values = []
        cursor = None
        for item in self.store.iterate(current.project_id, before):
            try:
                item = self.get(item["id"], actor)
                values.append({**{key: item[key] for key in ("id", "name", "format", "created_at", "project_id", "manifest_digest")},
                               "file_count": len(item["files"]), "total_bytes": sum(source["size"] for source in item["files"]),
                               "safety": self.safety.effective(item)})
            except Failure as exc:
                if exc.status not in {403, 404}:
                    raise
            if len(values) == 50:
                cursor = item["id"]
                break
        return {"datasets": values, "next_cursor": cursor, "provider_available": self.artifacts.driver is not None}

    async def create(self, body, key, actor, *, origin=None, safety_sources=()):
        self.service.live()
        body = CreateDataset.model_validate(body).model_dump(by_alias=True)
        key_check(key)
        if origin is not None:
            if not isinstance(origin, dict) or len(encoded(origin)) > 32768:
                raise Failure("origin_limit", "The internal dataset origin exceeds 32 KiB.", 413)
            origin = copy.deepcopy(origin)
        request_digest = hashlib.sha256(encoded(body if origin is None else {**body, "origin": origin})).hexdigest()
        async with self.admission:
            current = self.service.auth.current(actor)
            current.require("files:write")
            previous = self.store.existing(current.subject_id, current.project_id, key, request_digest)
            if previous:
                return self.view(self.get(previous["id"], actor))
            lineage = list(body["provenance"]["input_dataset_ids"])
            if body["previous_version_id"]:
                lineage.append(body["previous_version_id"])
            for identity in lineage:
                self.get(identity, actor)
            sources = []
            for entry in body.pop("sources"):
                sources.append(await self.artifacts.snapshot(entry, actor))
            if len({source["name"] for source in sources}) != len(sources):
                raise Failure("duplicate_name", "Dataset files must have distinct names.", 409)
            with self.service.store.lock, self.service.store.db:
                current = self.service.auth.current(actor)
                current.require("files:write")
                for source in sources:
                    self.artifacts.capability(source, actor)
                for identity in lineage:
                    self.get(identity, actor)
                value = seal({"id": secrets.token_hex(16), "version": 1, **body, **({"origin": origin} if origin is not None else {}), "files": sources,
                    "subject_id": current.subject_id, "project_id": current.project_id, "created_at": time.time()}, self.store.key)
                self.store.insert(value, key, request_digest)
                self.safety.register(value, safety_sources)
                self.service.store.audit("dataset.create", value["id"], "verified", actor,
                    subject_id=current.subject_id, project_id=current.project_id)
            if hasattr(self.service, "inspections"):
                await self.service.inspections.on_create(value, actor)
            return self.view(value)

    async def inputs(self, identity, actor):
        value = self.get(identity, actor)
        self.safety.require(value)
        for source in value["files"]:
            await self.artifacts.verify(source, actor)
        self.safety.require(self.get(identity, actor))
        return {"dataset_id": value["id"], "manifest_digest": value["manifest_digest"],
                "project_id": value["project_id"], "files": copy.deepcopy(value["files"])}

    async def read(self, identity, index, actor, offset, limit=262144):
        value = self.get(identity, actor)
        self.safety.require(value)
        if type(index) is not int or not 0 <= index < len(value["files"]):
            raise Failure("not_found", "The dataset file was not found.", 404)
        result = await self.artifacts.read(value["files"][index], actor, offset, limit)
        self.safety.require(self.get(identity, actor))
        return result
