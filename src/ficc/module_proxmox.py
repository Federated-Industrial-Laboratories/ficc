# SPDX-License-Identifier: Apache-2.0
"""Bind Proxmox VM batches to enrollment, grants and durable task identity."""

import asyncio
import copy
import secrets
import time

from ficc_node import proxmox_spec as spec
from ficc_node.proxmox_compat import require_console, require_power, require_read
from ficc_node.vm_libvirt import ProviderError

from .errors import Failure
from .module_proxmox_store import Records
from .module_vm import VMs
from .module_vm_operations import Operations
from .module_vm_store import node_identity
from .providers.proxmox import CONSOLE_COMMAND, Transport

PRIMITIVES = {"vm.proxmox.list": "vm:read", "vm.proxmox.status": "vm:read",
              "vm.proxmox.preview": "vm:power", "vm.proxmox.operation": "vm:read"}


class Proxmox(Operations):
    terminal_states = spec.TERMINAL
    profiles = VMs.profiles
    remove_profile = VMs.remove_profile

    def __init__(self, service):
        self.service = service
        self.records = Records(service.store)
        self.transport = Transport(service)
        self.controller = service.store.get_setting("controller_id", None) or secrets.token_hex(16)
        service.store.set_setting("controller_id", self.controller)
        self.previews = {}
        self.admission = asyncio.Lock()
        self.preview_pending = 0
        self.inflight = set()

    @staticmethod
    def resource_id(profile_id, domain_id):
        return f"proxmox-{profile_id}-{domain_id}"

    async def set_profile(self, actor, node_id, enabled=True):
        async with self.admission:
            self.service.live()
            self.service.authorize(actor, "nodes:write", node_id)
            self.service.authorize(actor, "vm:read", node_id)
            if type(enabled) is not bool:
                raise Failure("vm_invalid_profile", "Choose an explicit Proxmox profile state.")
            node = self.service.store.node(node_id)
            identity = node_identity(node)
            def check():
                self.service.live()
                self.service.authorize(actor, "nodes:write", node_id)
                self.service.authorize(actor, "vm:read", node_id)
                if node_identity(self.service.store.node(node_id)) != identity:
                    raise Failure("vm_profile_changed", "The enrolled system changed during Proxmox discovery.", 409)
            prior = next((item for item in self.records.profiles() if item["node_id"] == node_id), None)
            # Disable stays available when the system is offline or changed.
            if not enabled and prior:
                value = {**prior, "enabled": False, "revision": prior["revision"] + 1}
            else:
                provider = await self.transport.request(node, None, "discover", {}, check)
                try:
                    require_read(provider)
                except ProviderError as exc:
                    raise Failure(exc.code, exc.message, 409) from exc
                same = prior and prior["identity"] == identity and prior["provider"] == provider
                if not same and any(target["node_id"] == node_id
                        for operation in self.records.all() for target in operation["targets"]):
                    raise Failure("vm_busy", "Remove this system's VM receipts before replacing its Proxmox profile.", 409)
                value = {"id": prior["id"] if same and prior is not None else secrets.token_hex(16), "node_id": node_id,
                    "identity": identity, "connection": "local", "provider": provider,
                    "revision": prior["revision"] + 1 if prior else 1, "enabled": enabled}
            check()
            self.records.save_profile(value)
            self.service.store.audit("vm.proxmox.profile", node_id, actor=actor)
            return value

    def accept_receipt(self, target, receipt):
        super().accept_receipt(target, receipt)
        if "task" in receipt:
            target["task"] = copy.deepcopy(receipt["task"])

    def reconcile_receipt(self, target, receipt):
        if target["state"] in {"queued", "dispatching", "unknown", "accepted"}:
            target.pop("error", None)
            self.accept_receipt(target, receipt)

    def observe_receipt(self, action, target, observed):
        if "data" in observed:
            target["observed_state"] = observed["data"]["state"]
            target["observed_at"] = time.time()
            desired = {"off"} if action == "shutdown" else {"running", "blocked", "paused"}
            if (target["state"] == "accepted" and target["observed_state"] in desired
                    and "task" in target and spec.task_succeeded(target["task"])):
                target["state"] = "observed"

    async def resolve(self, actor, operation_id, vm_ids, check):
        if (not isinstance(vm_ids, list) or not 1 <= len(vm_ids) <= 64
                or any(not isinstance(item, str) for item in vm_ids) or len(set(vm_ids)) != len(vm_ids)):
            raise Failure("vm_invalid_selection", "Select one to64 distinct VM outcomes.")
        await self.operation(actor, operation_id, check)
        value = self.records.get(operation_id)
        self.local_authority(actor, value, "vm:power", check)
        selected = [item for item in value["targets"] if item["vm_id"] in vm_ids]
        if len(selected) != len(vm_ids):
            raise Failure("vm_invalid_selection", "Select VM outcomes from this operation.")
        if any("task" in item and item["task"]["state"] != "stopped" for item in selected):
            raise Failure("vm_task_active", "Read a stopped provider task result before resolving its outcome.", 409)
        pending = [item["vm_id"] for item in selected if item["state"] in {"accepted", "unknown"}]
        if not pending:
            return self.public_operation(value)
        return await super().resolve(actor, operation_id, pending, check)

    @staticmethod
    def public_preview(value):
        return {**VMs.public_preview(value), "provider": "proxmox"}

    @staticmethod
    def public_operation(value):
        result = {**VMs.public_operation(value), "provider": "proxmox"}
        for public, target in zip(result["targets"], value["targets"], strict=True):
            if "task" in target:
                public["task"] = copy.deepcopy(target["task"])
        return result

    async def console(self, actor, digest, instance_id, node_id, vm_id, check):
        _, grouped = self.groups([node_id], [vm_id])
        node, profile = self.profile(node_id)
        guard = self.guard(actor, digest, node_id, "vm:console", profile, check)
        graphics = await self.transport.request(node, profile, "console", {"uuids": grouped[node_id]}, guard)
        return {"actor": actor, "digest": digest, "instance_id": instance_id, "node_id": node_id,
            "profile": profile, "vm_id": vm_id, "graphics": graphics, "expires_at": time.time() + 60,
            "provider": "proxmox"}

    async def console_command(self, descriptor, check):
        value = copy.deepcopy(descriptor)
        if value["expires_at"] < time.time() or value["provider"] != "proxmox":
            raise Failure("vm_console_expired", "The Proxmox console reference expired.", 409)
        node, profile = self.profile(value["node_id"])
        if profile != value["profile"]:
            raise Failure("vm_profile_changed", "The Proxmox console profile changed.", 409)
        guard = self.guard(value["actor"], value["digest"], value["node_id"], "vm:console", profile, check)
        profile_id, domain_id = spec.resource(value["vm_id"])
        if profile_id != profile["id"] or domain_id != value["graphics"]["uuid"]:
            raise Failure("vm_invalid_console", "The Proxmox console identity is invalid.")
        request = {"version": 1, "action": "console", "connection": "local", "provider": profile["provider"],
                   "profile": profile["id"], "parameters": {"uuids": [domain_id]}}
        arguments = await self.service.ssh.arguments(node)
        guard()
        return arguments + [CONSOLE_COMMAND], spec.encode({"request": request}) + b"\n"


    def profile(self, node_id):
        value = self.records.profile(node_id)
        node = self.service.store.node(node_id)
        if not value["enabled"]:
            raise Failure("vm_profile_disabled", "The proxmox profile is disabled.", 409)
        if value["identity"] != node_identity(node):
            raise Failure("vm_profile_changed", "The enrolled identity changed; configure proxmox again.", 409)
        return node, value

    def guard(self, actor, digest, node_id, capability, profile, check, recovery=False):
        def current():
            check()
            self.service.live()
            self.service.authorize(actor, "nodes:read", node_id)
            self.service.authorize(actor, capability, node_id)
            self.service.modules.require(digest, capability, [node_id])
            try:
                if capability == "vm:power" and not recovery:
                    require_power(profile["provider"])
                elif capability == "vm:console":
                    require_console(profile["provider"])
            except ProviderError as exc:
                raise Failure(exc.code, exc.message, 409) from exc
            if capability != "vm:read":
                self.service.authorize(actor, "vm:read", node_id)
                self.service.modules.require(digest, "vm:read", [node_id])
            _, latest = self.profile(node_id)
            keys = set(profile) - ({"revision", "enabled"} if recovery else set())
            if any(latest[key] != profile[key] for key in keys):
                raise Failure("vm_profile_changed", "The proxmox profile changed after this request.", 409)
        current()
        return current

    def groups(self, node_ids, vm_ids):
        if (not isinstance(vm_ids, list) or not 1 <= len(vm_ids) <= 64
                or any(not isinstance(item, str) for item in vm_ids) or len(set(vm_ids)) != len(vm_ids)):
            raise Failure("vm_invalid_selection", "Select one to 64 distinct VMs.")
        grouped: dict[str, list[str]] = {}
        profiles = {node_id: self.profile(node_id) for node_id in node_ids}
        lookup = {profile["id"]: node_id for node_id, (_, profile) in profiles.items()}
        for vm_id in vm_ids:
            try:
                profile_id, domain_id = spec.resource(vm_id)
            except ValueError as exc:
                raise Failure("vm_invalid_selection", "The VM resource identity is invalid.") from exc
            node_id = lookup.get(profile_id)
            if node_id is None:
                raise Failure("vm_target_denied", "The VM is outside the selected system profiles.", 403)
            grouped.setdefault(node_id, []).append(domain_id)
        return profiles, grouped

    async def read(self, actor, call):
        action = call.primitive.rsplit(".", 1)[1]
        if action == "list":
            spec.fields(call.parameters, set(), {"offset", "limit"})
            offset = spec.integer(call.parameters.get("offset", 0), 0, 4096)
            limit = min(spec.integer(call.parameters.get("limit", 64), 1, 64), 256 // len(call.target_ids))
            profiles, grouped = {}, {}
        else:
            spec.fields(call.parameters, {"vm_ids"})
            profiles, grouped = self.groups(call.target_ids, call.parameters["vm_ids"])

        async def one(node_id):
            try:
                node, profile = profiles.get(node_id) or self.profile(node_id)
                check = self.guard(actor, call.package_digest, node_id, "vm:read", profile, call.check)
                if action == "status" and node_id not in grouped:
                    return {"target": node_id, "data": {"results": []}}
                params = {"offset": offset, "limit": limit} if action == "list" else {"uuids": grouped[node_id]}
                value = await self.transport.request(node, profile, action, params, check)
                for item in value["results"]:
                    item["vm_id"] = f"proxmox-{profile['id']}-{item['uuid']}"
                return {"target": node_id, "data": value}
            except Failure as exc:
                return {"target": node_id, "error": {"code": exc.code, "message": exc.message}}
        result = await asyncio.gather(*(one(node_id) for node_id in call.target_ids))
        call.check()
        return result

    async def broker(self, actor, call, instance_id):
        capability = PRIMITIVES.get(call.primitive)
        if (capability is None or capability not in call.action_capabilities
                or call.primitive == "vm.proxmox.preview" and "vm:read" not in call.action_capabilities):
            raise Failure("module_primitive_denied", "The VM primitive is not permitted.", 403)
        spec.text(instance_id, 128)
        try:
            if call.primitive in {"vm.proxmox.list", "vm.proxmox.status"}:
                return await self.read(actor, call)
            if call.primitive == "vm.proxmox.preview":
                spec.fields(call.parameters, {"action", "vm_ids"})
                value = await self.preview(actor, call.package_digest, instance_id, list(call.target_ids),
                                           call.parameters, call.check)
                return [{"target": node_id, "data": value if index == 0 else {**value, "vms": []}}
                        for index, node_id in enumerate(call.target_ids)]
            spec.fields(call.parameters, {"operation_id"})
            value = self.records.get(call.parameters["operation_id"])
            if (value["package_digest"] != call.package_digest or value["instance_id"] != instance_id
                    or any(item["node_id"] not in call.target_ids for item in value["targets"])):
                raise Failure("vm_target_denied", "The operation is outside this module instance.", 403)
            result = await self.operation(actor, value["id"], call.check)
            return [{"target": node_id, "data": {"operation": result if index == 0 else None}}
                    for index, node_id in enumerate(call.target_ids)]
        except (ValueError, TypeError, KeyError) as exc:
            raise Failure("vm_invalid_request", "The VM request is invalid.") from exc
