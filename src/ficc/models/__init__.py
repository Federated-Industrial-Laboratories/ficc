# SPDX-License-Identifier: Apache-2.0
"""Project model catalogue and verified cache, independent of runtime adapters."""
import asyncio
import hashlib
import secrets
import time

from ..errors import Failure
from ..execution.spec import ObjectReference, digest
from ..inference.records import Records
from .cache import Cache
from .schema import Manifest, Record


class Models:
    def __init__(self, service):
        self.service = service
        self.records = Records(service.store, "model_revisions")
        from pathlib import Path
        configured = service.store.get_setting("models.directory", None)
        path = Path(configured) if configured else service.settings.state_dir / "models"
        if configured:
            info = path.lstat()
            expected = service.store.get_setting("models.directory_binding", None)
            if expected != [info.st_dev, info.st_ino]:
                raise ValueError("The configured model volume is absent or has changed; restore its mount before starting.")
        self.root = Cache(path)
        self.caches = {}
        self.downloads = {}

    def cache_for(self, value):
        self.root.check()
        project = value["project_id"]
        if project not in self.caches:
            self.caches[project] = Cache(self.root.root / project)
        return self.caches[project]

    async def close(self):
        tasks = [item["task"] for item in self.downloads.values()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def current(self, actor, scope):
        value = actor if getattr(actor, "kind", None) == "workload" else self.service.auth.current(actor.id if hasattr(actor, "id") else actor)
        value.require(scope)
        if value.node_ids is not None or value.root_ids is not None:
            raise Failure("denied", "Model access requires a project credential without machine restrictions.", 403)
        return value

    def get(self, identity, actor, scope="models:read"):
        actor = self.current(actor, scope)
        value = self.records.get(identity)
        actor.require_record(value)
        checked = Record.model_validate(value)
        if checked.manifest_digest != digest(checked.manifest.model_dump()):
            raise Failure("model_manifest_changed", "The retained immutable model manifest is corrupt.", 409)
        return value

    def view(self, value):
        manifest = Manifest.model_validate(value["manifest"])
        files = [{**item.model_dump(), **self.cache_for(value).status(item)} for item in manifest.files]
        return {**value, "files": files, "ready": all(item["complete"] for item in files),
                "total_bytes": sum(item.bytes for item in manifest.files), "download": self.downloads.get(value["id"], {}).get("state")}

    def create(self, body, actor):
        actor = self.current(actor, "models:manage")
        manifest = Manifest.model_validate(body)
        binding = digest(manifest.model_dump())
        for value in self.records.all(actor.project_id):
            if value["manifest_digest"] == binding:
                return self.view(value)
        value = Record(id=secrets.token_hex(16), project_id=actor.project_id, subject_id=actor.subject_id,
                       manifest=manifest, manifest_digest=binding, created_at=time.time()).model_dump()
        self.records.save(value)
        return self.view(value)

    def references(self, value):
        return [ObjectReference(id=hashlib.sha256(f"{value['id']}:{index}:{item.digest}".encode()).hexdigest()[:32],
                                name=item.name, digest=item.digest, bytes=item.bytes, delivery="stream")
                for index, item in enumerate(Manifest.model_validate(value["manifest"]).files)]

    def bind(self, identity, actor):
        value = self.get(identity, actor)
        if not self.view(value)["ready"]:
            raise Failure("model_missing", "Complete and verify every model file before deployment.", 409)
        return value

    async def read(self, identity, index, actor, offset, length):
        value = self.get(identity, actor)
        item = Manifest.model_validate(value["manifest"]).files[index]
        return await asyncio.to_thread(self.cache_for(value).read, item, offset, length)

    def remove(self, identity, actor, *, evict=False):
        value = self.get(identity, actor, "models:manage")
        if any(row["spec"].get("model_id") == identity for row in self.service.inference.records.all()):
            raise Failure("model_in_use", "Remove referencing inference services before deleting this model revision.", 409)
        if any(job.request.model_revision == identity for job in self.service.workloads.records.jobs()):
            raise Failure("model_in_use", "Remove referencing workloads before deleting this model revision.", 409)
        task = self.downloads.get(identity, {}).get("task")
        if task and not task.done():
            raise Failure("model_downloading", "Wait for the current acquisition to finish before removal.", 409)
        if evict:
            other = {item["digest"] for row in self.records.all(value["project_id"]) if row["id"] != identity for item in row["manifest"]["files"]}
            for item in Manifest.model_validate(value["manifest"]).files:
                if item.digest not in other:
                    self.cache_for(value).evict(item)
        self.records.remove(identity)
        return {"removed": True, "id": identity}
