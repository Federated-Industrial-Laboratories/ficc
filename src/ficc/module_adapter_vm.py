# SPDX-License-Identifier: Apache-2.0
"""Map installed VM adapters to host grants, tables, confirmations and displays."""

import asyncio
import copy
import re
import secrets
import time

from .errors import Failure
from .module_adapter_operations import AdapterOperations
from .module_adapter_store import IMMUTABLE
from .modules import adapter_protocol as spec
from .modules.adapter_manifest import ADMIN
from .modules.validation import fields, identifier

RESOURCE = re.compile(r"vm-([0-9a-f]{32})-([0-9a-f]{32})\Z")
PRIMITIVES = {"vm.adapter.profiles": "vm:read", "vm.adapter.list": "vm:read", "vm.adapter.status": "vm:read",
              "vm.adapter.preview": "vm:power", "vm.adapter.operation": "vm:read"}


class AdapterVMs(AdapterOperations):
    def __init__(self, service, adapters=None):
        self.service = service
        self.adapters = adapters if adapters is not None else service.adapters
        self.records = self.adapters.records
        self.controller = service.store.get_setting("controller_id", None) or secrets.token_hex(16)
        service.store.set_setting("controller_id", self.controller)
        self.previews = {}
        self.preview_pending = 0
        self.admission = asyncio.Lock()
        self.inflight = set()
        self.tasks: set[asyncio.Task] = set()
        self.resources: dict[str, dict[str, dict]] = {}

    @staticmethod
    def resource_id(profile_id, domain_id):
        return f"vm-{profile_id}-{domain_id}"

    def profile(self, profile_id):
        profile = self.adapters.profile(profile_id)
        if profile["endpoint_kind"] == "linux-ssh":
            endpoint = self.service.store.node(profile["endpoint_id"])
        else:
            endpoint = self.adapters.transport.windows.endpoint(profile["endpoint_id"])
        return endpoint, profile

    def guard(self, actor, digest, node_id, capability, profile, check, recovery=False):
        def current():
            check()
            self.service.live()
            for scope in {"nodes:read", "vm:read", capability}:
                self.service.authorize(actor, scope, node_id)
            for scope in {"vm:read", capability}:
                self.service.modules.require(digest, scope, [node_id])
            latest = self.adapters.profile(profile["id"])
            keys = IMMUTABLE | {"provider"} if recovery else set(profile)
            if profile["endpoint_id"] != node_id or any(latest.get(key) != profile.get(key) for key in keys):
                raise Failure("adapter_profile_changed", "The frozen provider profile changed.", 409)
            self.service.modules.require(profile["digest"], ADMIN, [profile["id"]])
        current()
        return current

    def groups(self, node_ids, vm_ids):
        if (not isinstance(vm_ids, list) or not 1 <= len(vm_ids) <= 64
                or any(not isinstance(item, str) for item in vm_ids) or len(set(vm_ids)) != len(vm_ids)):
            raise Failure("vm_invalid_selection", "Select one to 64 distinct VMs.")
        profiles: dict[str, dict] = {}
        grouped: dict[str, list[dict]] = {}
        for vm_id in vm_ids:
            match = RESOURCE.fullmatch(vm_id)
            if match is None:
                raise Failure("vm_invalid_selection", "The VM resource identity is invalid.")
            profile_id, resource_id = match.groups()
            profile = self.adapters.profile(profile_id)
            if profile["endpoint_id"] not in node_ids:
                raise Failure("vm_target_denied", "The VM is outside the panel's selected systems.", 403)
            resource = self.resources.get(profile_id, {}).get(resource_id)
            if resource is None:
                raise Failure("adapter_inventory_required", "Read the provider inventory before selecting this VM.", 409)
            profiles[profile_id] = profile
            grouped.setdefault(profile_id, []).append(copy.deepcopy(resource))
        return profiles, grouped

    def remember(self, profile, rows, *, reset=False):
        if reset:
            self.resources[profile["id"]] = {}
        known = self.resources.setdefault(profile["id"], {})
        for item in rows:
            resource = item["resource"]
            known[resource["id"]] = copy.deepcopy(resource)
            if len(known) > 256:
                del known[next(iter(known))]
        live = {item["id"] for item in self.records.profiles()}
        self.resources = {key: value for key, value in self.resources.items() if key in live}

    @staticmethod
    def public_row(profile, row):
        resource = row["resource"]
        return {"uuid": resource["id"], "vm_id": f"vm-{profile['id']}-{resource['id']}",
                "profile_id": profile["id"], "data": {"uuid": resource["id"], "definition": resource["revision"],
                "name": row["name"], "state": resource["state"], "memory_kib": row["memory_kib"],
                "vcpus": row["vcpus"], "console": row["console"], "identity_ready": resource["birth"] != "0" * 64}}

    async def read(self, actor, call):
        if call.primitive == "vm.adapter.profiles":
            fields(call.parameters, set(), {"adapter_id"})
            requested = identifier(call.parameters["adapter_id"]) if "adapter_id" in call.parameters else None
            choices_by_target: dict[str, list[dict]] = {node_id: [] for node_id in call.target_ids}
            for profile in self.records.profiles():
                node_id = profile["endpoint_id"]
                if node_id not in choices_by_target:
                    continue
                try:
                    self.guard(actor, call.package_digest, node_id, "vm:read", profile, call.check)
                    package = self.service.modules.get(profile["digest"])["manifest"]
                    if requested is None or requested == package["id"]:
                        choices_by_target[node_id].append({"id": profile["id"], "label":
                            package.get("display_name", package["id"]) + " / " + profile["id"][:8]})
                except Failure:
                    continue
            call.check()
            return [{"target": node_id, "data": {"profiles": choices}}
                    for node_id, choices in choices_by_target.items()]
        phase = "inventory" if call.primitive == "vm.adapter.list" else "status"
        fields(call.parameters, {"profile_id"}, {"offset", "limit"} if phase == "inventory" else {"vm_ids"})
        profile = self.adapters.profile(spec.identity(call.parameters["profile_id"]))
        node_id = profile["endpoint_id"]
        if node_id not in call.target_ids:
            raise Failure("vm_target_denied", "The provider is outside this panel's selected systems.", 403)
        guard = self.guard(actor, call.package_digest, node_id, "vm:read", profile, call.check)
        if phase == "inventory":
            offset = spec.integer(call.parameters.get("offset", 0), 0, 4096)
            limit = spec.integer(call.parameters.get("limit", 64), 1, 128)
            value = await self.adapters.execute(profile, phase, phase, [], {"offset": offset, "limit": limit}, guard)
            self.remember(profile, value["resources"], reset=offset == 0)
            data = {"results": [self.public_row(profile, item) for item in value["resources"]],
                    "next_offset": value["next_offset"], "truncated": value["truncated"], "profile_id": profile["id"]}
        else:
            profiles, grouped = self.groups(call.target_ids, call.parameters.get("vm_ids"))
            if set(profiles) != {profile["id"]}:
                raise Failure("vm_target_denied", "Select VMs from the chosen provider profile.", 403)
            value = await self.adapters.execute(profile, phase, phase, grouped[profile["id"]], {}, guard)
            rows = [item["data"] for item in value["results"] if "data" in item]
            self.remember(profile, rows)
            data = {"results": [self.public_row(profile, item["data"]) if "data" in item else
                {"uuid": item["id"], "vm_id": self.resource_id(profile["id"], item["id"]), "error": item["error"]}
                for item in value["results"]], "profile_id": profile["id"]}
        guard()
        return [{"target": target, "data": data if target == node_id else {"results": []}} for target in call.target_ids]

    async def preview(self, actor, digest, instance_id, node_ids, parameters, check):
        fields(parameters, {"action", "vm_ids", "profile_id"})
        action = parameters["action"]
        if action not in {"start", "shutdown"}:
            raise Failure("vm_action_denied", "Select start or graceful shutdown.")
        self.previews = {key: value for key, value in self.previews.items() if value["expires_at"] > time.time()}
        if len(self.previews) + self.preview_pending >= 64:
            raise Failure("vm_preview_capacity", "The VM confirmation preview limit is full.", 429)
        self.preview_pending += 1
        try:
            profiles, grouped = self.groups(node_ids, parameters["vm_ids"])
            if set(profiles) != {spec.identity(parameters["profile_id"])}:
                raise Failure("vm_target_denied", "Select VMs from the chosen provider profile.", 403)
            targets = []
            for profile_id, resources in grouped.items():
                profile = profiles[profile_id]
                guard = self.guard(actor, digest, profile["endpoint_id"], "vm:power", profile, check)
                status = await self.adapters.execute(profile, "status", "status", resources, {}, guard)
                rows = []
                for returned in status["results"]:
                    if "error" in returned:
                        raise Failure(returned["error"]["code"], returned["error"]["message"], 409)
                    row = returned["data"]
                    if row["resource"]["state"] not in ({"off"} if action == "start" else {"running", "blocked", "paused"}):
                        raise Failure("vm_state_conflict", "A selected VM cannot perform this action in its current state.", 409)
                    rows.append(row)
                resources = [row["resource"] for row in rows]
                if any(resource["birth"] == "0" * 64 for resource in resources):
                    raise Failure("adapter_identity_required", "Run the adapter's documented identity setup before VM power or display access.", 409)
                prepared = await self.adapters.execute(profile, "prepare", action, resources, {}, guard)
                for row, result in zip(rows, prepared["results"], strict=True):
                    if "error" in result:
                        raise Failure(result["error"]["code"], result["error"]["message"], 409)
                    resource = row["resource"]
                    targets.append({"node_id": profile["endpoint_id"], "profile": profile,
                        "vm_id": self.resource_id(profile_id, resource["id"]), "resource": resource,
                        "expected": {"uuid": resource["id"], "definition": resource["revision"], "state": resource["state"]},
                        "adapter_intent": result["intent"], "name": row["name"], "state": "queued"})
            check()
            value = {"id": secrets.token_hex(16), "actor": actor, "package_digest": digest,
                "instance_id": instance_id, "action": action, "targets": targets,
                "expires_at": time.time() + 120, "check": check}
            self.previews[value["id"]] = value
            return self.public_preview(value)
        finally:
            self.preview_pending -= 1

    async def broker(self, actor, call, instance_id):
        capability = PRIMITIVES.get(call.primitive)
        if (capability is None or capability not in call.action_capabilities
                or capability == "vm:power" and "vm:read" not in call.action_capabilities):
            raise Failure("module_primitive_denied", "The VM primitive is not permitted.", 403)
        spec.identity(instance_id)
        try:
            if call.primitive in {"vm.adapter.profiles", "vm.adapter.list", "vm.adapter.status"}:
                return await self.read(actor, call)
            if call.primitive == "vm.adapter.preview":
                result = await self.preview(actor, call.package_digest, instance_id, call.target_ids, call.parameters, call.check)
                return [{"target": target, "data": result if index == 0 else {**result, "vms": []}}
                        for index, target in enumerate(call.target_ids)]
            fields(call.parameters, {"operation_id"})
            value = self.records.get(call.parameters["operation_id"])
            if (value["package_digest"] != call.package_digest or value["instance_id"] != instance_id
                    or any(item["node_id"] not in call.target_ids for item in value["targets"])):
                raise Failure("vm_target_denied", "The operation is outside this module instance.", 403)
            result = await self.operation(actor, value["id"], call.check)
            return [{"target": target, "data": {"operation": result if index == 0 else None}}
                    for index, target in enumerate(call.target_ids)]
        except (ValueError, TypeError, KeyError) as exc:
            raise Failure("vm_invalid_request", "The provider VM request is invalid.") from exc

    async def console_request(self, actor, call, instance_id):
        fields(call.parameters, {"profile_id", "vm_ids"})
        if not isinstance(call.parameters["vm_ids"], list) or len(call.parameters["vm_ids"]) != 1:
            raise Failure("viewer_selection", "Select exactly one VM for a display session.")
        profiles, grouped = self.groups(call.target_ids, call.parameters["vm_ids"])
        if set(profiles) != {spec.identity(call.parameters["profile_id"])}:
            raise Failure("vm_target_denied", "Select a VM from the chosen provider profile.", 403)
        profile = next(iter(profiles.values()))
        if grouped[profile["id"]][0]["birth"] == "0" * 64:
            raise Failure("adapter_identity_required", "Run the adapter's documented identity setup before VM power or display access.", 409)
        guard = self.guard(actor, call.package_digest, profile["endpoint_id"], "vm:console", profile, call.check)
        result = await self.adapters.execute(profile, "console", "console", grouped[profile["id"]], {}, guard)
        graphics = await self.adapters.transport.console_descriptor(profile, result, guard)
        return {"provider": "adapter", "actor": actor, "digest": call.package_digest, "instance_id": instance_id,
                "node_id": profile["endpoint_id"], "profile_id": profile["id"], "profile": profile,
                "vm_id": call.parameters["vm_ids"][0], "graphics": graphics,
                "proposal": result, "expires_at": time.time() + 60}

    def console_guard(self, descriptor, check):
        if descriptor["expires_at"] < time.time() or descriptor["provider"] != "adapter":
            raise Failure("vm_console_expired", "The provider display reference expired.", 409)
        return self.guard(descriptor["actor"], descriptor["digest"], descriptor["node_id"], "vm:console", descriptor["profile"], check)

    async def console_command(self, descriptor, check):
        guard = await self.console_current(descriptor, check)
        return await self.adapters.transport.console_command(descriptor, guard)

    async def console_connection(self, descriptor, check):
        guard = await self.console_current(descriptor, check)
        return await self.adapters.transport.console_connection(descriptor, guard)

    async def console_current(self, descriptor, check):
        guard = self.console_guard(descriptor, check)
        proposal = descriptor["proposal"]
        current = await self.adapters.execute(descriptor["profile"], "console", "console",
            [proposal["resource"]], {}, guard)
        if current != proposal:
            raise Failure("adapter_console_changed", "The provider display changed after selection.", 409)
        return guard
