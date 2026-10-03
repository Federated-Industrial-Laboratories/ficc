# SPDX-License-Identifier: Apache-2.0
"""Load trusted storage packages behind host-authorized registered-file capabilities."""

import hashlib
import importlib.metadata
import json
import stat

from ficc_node.file_access import CHUNK
from ficc_node.job_state import digest

from .errors import Failure
from .state_provider import read_private


class FileCapability:
    def __init__(self, files, authority, root, reference):
        self.files, self.authority, self.root, self.reference = files, authority, root, reference

    async def call(self, action, **values):
        if action not in {"file.stat", "file.hash", "file.read"}:
            raise Failure("artifact_action", "The provider requested an unsupported file action.", 409)
        return await self.files.transport.call(self.root, {**values, "action": action, "entry": self.reference},
            check=lambda: self.files.check_principal(self.authority(), "files:read", self.root),
            timeout=None if action == "file.hash" else 15)


class Artifacts:
    def __init__(self, service):
        self.service = service
        self.driver = None
        self.provider_version = None
        path = service.settings.state_dir / "artifact-provider.json"
        config = json.loads(read_private(path)) if path.exists() or path.is_symlink() else {"provider": "filesystem", "configuration": {}}
        if (not isinstance(config, dict) or set(config) != {"provider", "configuration"}
                or not isinstance(config["provider"], str) or not isinstance(config["configuration"], dict)):
            raise ValueError("The artifact provider configuration is invalid.")
        self.identity = config["provider"]
        entries = list(importlib.metadata.entry_points(group="ficc.artifact", name=self.identity))
        if len(entries) > 1:
            raise ValueError("Install exactly one selected artifact provider.")
        if entries:
            module = entries[0].load()
            if module.API_VERSION != 1:
                raise ValueError("The artifact provider interface version is unsupported.")
            self.driver = module.configure(config["configuration"])
            self.provider_version = entries[0].dist.version if entries[0].dist else "unknown"

    def available(self):
        if self.driver is None:
            raise Failure("artifact_provider_unavailable", "Install the trusted ficc-artifact-filesystem runtime package to register datasets.", 409)
        return self.driver

    def current(self, actor):
        """Internal callers may supply a callback which checks a durable delegation."""
        return actor() if callable(actor) else self.service.auth.current(actor)

    def capability(self, source, actor):
        files = self.service.files
        if source.get("provider", self.identity) != self.identity:
            raise Failure("artifact_provider_changed", "Select the original artifact provider to use this dataset.", 409)
        root = files.store.root(source["root_id"])
        files.check_principal(self.current(actor), "files:read", root)
        if root["revision"] != source["root_revision"]:
            raise Failure("source_changed", "The registered dataset source changed.", 409)
        return FileCapability(files, lambda: self.current(actor), root, source["reference"])

    async def snapshot(self, entry, actor):
        files = self.service.files
        root, reference = files.resolve(entry["root_id"], entry["entry_id"], actor)
        if reference["identity"]["type"] != stat.S_IFREG:
            raise Failure("unsupported_file", "Select ordinary files as dataset sources.", 409)
        source = {"root_id": root["id"], "root_revision": root["revision"], "reference": reference}
        result = await self.available().snapshot(self.capability(source, actor))
        if (type(result.get("size")) is not int or result.get("size") != reference["identity"]["size"] or result.get("identity") != reference["identity"]
                or not isinstance(result.get("name"), str) or not 1 <= len(result["name"]) <= 1024
                or not isinstance(result.get("sha256"), str) or len(result["sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in result["sha256"])):
            raise Failure("artifact_response", "The artifact provider returned an invalid snapshot.", 502)
        return {**source, **{key: result[key] for key in ("name", "size", "sha256")},
                "provider": self.identity, "provider_version": self.provider_version,
                "snapshot_id": digest({"root_id": root["id"], "root_revision": root["revision"], "identity": result["identity"], "sha256": result["sha256"]})}

    async def verify(self, source, actor):
        result = await self.available().snapshot(self.capability(source, actor))
        if (result.get("sha256") != source["sha256"] or result.get("size") != source["size"]
                or result.get("identity") != source["reference"]["identity"]):
            raise Failure("source_changed", "The dataset source differs from its immutable snapshot.", 409)

    async def read(self, source, actor, offset, limit=CHUNK):
        if type(offset) is not int or not 0 <= offset <= source["size"] or type(limit) is not int or not 1 <= limit <= CHUNK:
            raise Failure("invalid_offset", "Select a bounded range within the dataset file.")
        header, data = await self.available().read(self.capability(source, actor), offset, limit)
        if (not isinstance(data, bytes) or len(data) != min(limit, source["size"] - offset)
                or header.get("offset") != offset or header.get("next_offset") != offset + len(data)
                or header.get("sha256") != hashlib.sha256(data).hexdigest()):
            raise Failure("artifact_response", "The artifact provider returned an invalid file range.", 502)
        return header, data
