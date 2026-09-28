# SPDX-License-Identifier: Apache-2.0
"""Select registered provider transports without exposing endpoints or credentials."""

import asyncio
import hashlib
import os
import re
import struct
import time

from ..backup_io import read
from ..errors import Failure
from ..module_vm_store import node_identity
from ..modules.adapter_protocol import identity
from ..modules.adapter_runtime import ControllerRuntime
from ..modules.archive import MAX_EXPANDED, MAX_FILE
from ..modules.validation import digest, dumps, fields, loads, text
from ..ssh import transport_failure
from .libvirt import entry

COMMAND = entry("adapter_rpc")
LOCAL_IPC_QUALIFIED = False


class EndpointTransport:
    def __init__(self, service, *, windows=None):
        self.service, self.windows = service, windows
        self.controller = ControllerRuntime()
        self.semaphore = asyncio.Semaphore(4)

    def endpoint(self, kind, endpoint_id):
        identity(endpoint_id)
        if kind == "windows":
            if self.windows is None:
                raise Failure("adapter_transport_unavailable", "The Windows endpoint transport is unavailable.", 503)
            value = self.windows.endpoint(endpoint_id)
            return {key: value[key] for key in ("id", "revision", "enabled", "machine_identity")}
        if kind != "linux-ssh":
            raise Failure("adapter_endpoint_invalid", "The provider endpoint type is unsupported.")
        node = self.service.store.node(endpoint_id)
        return {"id": node["id"], "revision": 1, "enabled": True, "machine_identity": node_identity(node)}

    @staticmethod
    def local_available():
        if not LOCAL_IPC_QUALIFIED:
            raise Failure("adapter_transport_unavailable", "The local provider IPC resource class is not qualified.", 503)

    async def rpc(self, endpoint_id, action, parameters, check, *, body=b"", timeout=10):
        node = self.service.store.node(endpoint_id)
        frozen = node_identity(node)
        def guard():
            check()
            if node_identity(self.service.store.node(endpoint_id)) != frozen:
                raise Failure("adapter_endpoint_changed", "The enrolled SSH identity changed.", 409)
        header = dumps({"version": 1, "action": action, "parameters": parameters})
        async with self.semaphore:
            guard()
            code, output, stderr = await self.service.ssh.command(node, COMMAND,
                struct.pack(">I", len(header)) + header + body, check=guard, timeout=timeout)
            guard()
        if code:
            if code == 42 or b"No module named" in stderr:
                raise Failure("adapter_helper_upgrade", "Install the current node helper for provider adapters.", 409)
            raise transport_failure(stderr)
        value = fields(loads(output), {"version"}, {"data", "error"})
        if type(value["version"]) is not int or value["version"] != 1 or ("data" in value) == ("error" in value):
            raise Failure("adapter_response_invalid", "The provider helper response is invalid.", 502)
        if "error" in value:
            fields(value["error"], {"code", "message"})
            raise Failure(text(value["error"]["code"], 96), text(value["error"]["message"], 256), 409)
        return value["data"]

    async def bindings(self, kind, endpoint_id, check):
        endpoint = self.endpoint(kind, endpoint_id)
        if kind == "windows":
            check()
            return [{"id": endpoint_id, "resource_kind": "winrm-jea", "available": endpoint["enabled"],
                     "identity": endpoint["machine_identity"], "label": "Registered Windows command endpoint"}]
        self.local_available()
        value = await self.rpc(endpoint_id, "binding-list", {}, check)
        fields(value, {"bindings"})
        if not isinstance(value["bindings"], list) or len(value["bindings"]) > 64:
            raise Failure("adapter_response_invalid", "The provider binding list exceeds its limit.", 502)
        for item in value["bindings"]:
            self.validate_descriptor(item)
        return value["bindings"]

    @staticmethod
    def validate_descriptor(value):
        fields(value, {"id", "resource_kind", "available", "identity", "label", "owner_uid"})
        identity(value["id"])
        digest(value["identity"])
        text(value["label"], 160)
        if (value["resource_kind"] != "unix-stream" or type(value["available"]) is not bool
                or type(value["owner_uid"]) is not int or not 0 <= value["owner_uid"] < 2**32):
            raise Failure("adapter_response_invalid", "The provider IPC binding is invalid.", 502)
        return value

    async def register_binding(self, kind, endpoint_id, parameters, check):
        self.endpoint(kind, endpoint_id)
        fields(parameters, {"socket_path"})
        path = text(parameters["socket_path"], 240)
        if kind != "linux-ssh" or not path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")[1:]):
            raise Failure("adapter_binding_invalid", "Select one absolute local provider socket path.")
        self.local_available()
        return self.validate_descriptor(await self.rpc(endpoint_id, "binding-register", {"socket_path": path}, check))

    async def validate_binding(self, kind, endpoint_id, binding_id, check):
        choices = await self.bindings(kind, endpoint_id, check)
        if not any(item["id"] == binding_id and item["available"] for item in choices):
            raise Failure("adapter_binding_missing", "Register an available provider resource for this endpoint.", 409)

    async def install(self, selected, manifest, check):
        directory = self.service.modules.verify(selected["digest"])
        members, contents = [], []
        root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            total = 0
            for path, checksum in sorted(manifest["files"].items()):
                data = read(root, path, MAX_FILE)
                total += len(data)
                if total > MAX_EXPANDED or hashlib.sha256(data).hexdigest() != checksum:
                    raise Failure("adapter_package_changed", "The verified provider package changed before deployment.", 409)
                contents.append(data)
                members.append({"path": path, "size": len(data), "sha256": checksum})
        finally:
            os.close(root)
        # This transfer binds verified content to its original inspected package digest.
        # It does not claim to reconstruct the uploaded ZIP's compression or metadata.
        await self.rpc(selected["endpoint_id"], "install", {"digest": selected["digest"],
            "manifest": manifest, "members": members}, check, body=b"".join(contents), timeout=20)

    async def qualify(self, selected, manifest, check):
        if selected["endpoint_kind"] == "windows":
            await self.controller.qualify(check)
            return
        self.local_available()
        await self.validate_binding("linux-ssh", selected["endpoint_id"], selected["transport_binding_id"], check)
        await self.install(selected, manifest, check)
        result = await self.rpc(selected["endpoint_id"], "qualify", {"binding_id": selected["transport_binding_id"]}, check)
        if result != {"available": True}:
            raise Failure("module_sandbox_unavailable", "The node provider sandbox is unavailable.", 503)

    async def execute(self, selected, manifest, conversation, check):
        timeout = 20 if conversation.phase == "apply" else 10
        if selected["endpoint_kind"] == "linux-ssh":
            self.local_available()
            return await self.rpc(selected["endpoint_id"], "execute", {"binding_id": selected["transport_binding_id"],
                "digest": selected["digest"], "request": conversation.request}, check, timeout=timeout + 2)
        if self.windows is None:
            raise Failure("adapter_transport_unavailable", "The Windows endpoint transport is unavailable.", 503)
        deadline = time.monotonic() + timeout
        async def forward(call):
            check()
            call.check()
            if call.profile_id != selected["id"] or call.package_digest != selected["digest"]:
                raise Failure("adapter_target_denied", "The adapter transport profile changed.", 403)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Failure("module_timeout", "The adapter request reached its time limit.", 504)
            return await self.windows.execute(selected["endpoint_id"], selected["endpoint_revision"],
                selected["machine_identity"], call.commands, check=call.check, timeout=remaining)
        conversation.transport = forward
        try:
            async with asyncio.timeout(timeout):
                return await self.controller.execute(self.service.modules.root / selected["digest"], manifest, conversation)
        except TimeoutError as exc:
            raise Failure("module_timeout", "The adapter request reached its time limit.", 504) from exc

    async def forget(self, selected, intent, outcomes, check):
        check()
        if selected["endpoint_kind"] == "windows":
            return
        current = self.endpoint("linux-ssh", selected["endpoint_id"])
        if current["machine_identity"] != selected["machine_identity"]:
            raise Failure("adapter_endpoint_changed", "The node receipt belongs to a different enrolled identity.", 409)
        # Receipt removal is a fixed helper operation. It never executes a package.
        value = await self.rpc(selected["endpoint_id"], "forget", {"profile_id": selected["id"],
            "digest": selected["digest"], "intent": intent, "outcomes": outcomes}, check)
        if value != {"removed": True}:
            raise Failure("adapter_response_invalid", "The node did not acknowledge receipt removal.", 502)

    async def console_descriptor(self, selected, proposal, check):
        check()
        if proposal["binding_id"] != selected["transport_binding_id"]:
            raise Failure("adapter_console_invalid", "The display transport binding changed.", 409)
        if selected["endpoint_kind"] == "windows":
            fields(proposal["parameters"], {"vm_id"})
            value = proposal["parameters"]["vm_id"]
            if (proposal["kind"] != "vmconnect" or not isinstance(value, str)
                    or re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", value) is None):
                raise Failure("adapter_console_invalid", "The registered VM display identity is invalid.", 409)
            return {"protocol": "rdp", "authentication": "registered-account"}
        raise Failure("adapter_console_unavailable", "The local provider display resource is not qualified.", 503)

    async def console_command(self, descriptor, check):
        check()
        raise Failure("adapter_console_unavailable", "The local provider display resource is not qualified.", 503)

    async def console_connection(self, descriptor, check):
        selected, proposal = descriptor["profile"], descriptor["proposal"]
        await self.console_descriptor(selected, proposal, check)
        if selected["endpoint_kind"] != "windows" or self.windows is None:
            raise Failure("adapter_console_unavailable", "The registered display transport is unavailable.", 503)
        return await self.windows.console_connection(selected["endpoint_id"], selected["endpoint_revision"],
            selected["machine_identity"], proposal["parameters"]["vm_id"], check=check)
