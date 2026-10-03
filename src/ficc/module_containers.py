# SPDX-License-Identifier: Apache-2.0
"""Bind container modules to enrolled profiles, current grants and fixed APIs."""

import asyncio
import copy
import secrets
import time

from ficc_node import container_spec as spec

from .errors import Failure
from .module_containers_operations import Operations
from .module_containers_store import Records, node_identity
from .providers.containers import Transport

PRIMITIVES = {"container.list": "container:read", "container.status": "container:read", "container.logs": "container:logs",
              "container.preview": "container:power", "container.operation": "container:read"}


class Containers(Operations):
    def __init__(self, service):
        self.service = service
        self.records = Records(service.store)
        self.transport = Transport(service)
        self.controller = service.store.get_setting("controller_id", None) or secrets.token_hex(16)
        service.store.set_setting("controller_id", self.controller)
        self.resources, self.previews = {}, {}
        self.admission = asyncio.Lock()
        self.preview_pending = 0
        self.inflight = set()
        self.dispatches = set()

    async def set_profile(self, actor, node_id, provider, connection, context="", namespace="", profile_id=None, enabled=True):
        self.service.live()
        self.service.authorize(actor, "nodes:write", node_id)
        self.service.authorize(actor, "container:read", node_id)
        if provider not in spec.PROVIDERS or type(enabled) is not bool:
            raise Failure("container_profile", "Select Docker, Podman or Kubernetes.")
        prior = self.records.profile(profile_id) if profile_id else None
        if prior and prior["node_id"] != node_id:
            raise Failure("container_profile", "A container profile cannot change its enrolled system.")
        if not enabled:
            if prior is None:
                raise Failure("container_profile", "Select a registered profile to disable.")
            value = {**prior, "enabled": False, "revision": prior["revision"] + 1}
            self.records.save_profile(value)
            return value
        node = self.service.store.node(node_id)
        identity = node_identity(node)
        value = {"id": prior["id"] if prior else secrets.token_hex(16), "node_id": node_id, "identity": identity,
                 "provider": provider, "connection": connection, "context": context, "namespace": namespace, "binding": None}
        spec.config(value)
        def check():
            self.service.live()
            self.service.authorize(actor, "nodes:write", node_id)
            self.service.authorize(actor, "container:read", node_id)
            if node_identity(self.service.store.node(node_id)) != identity:
                raise Failure("container_profile_changed", "The enrolled system identity changed.", 409)
            if prior and self.records.profile(prior["id"]) != prior:
                raise Failure("container_profile_changed", "The registered container profile changed during its probe.", 409)
        result = await self.transport.request(node, value, "probe", {}, check)
        value.update({key: result[key] for key in ("binding", "version", "account_uid")})
        value.update(revision=prior["revision"] + 1 if prior else 1, enabled=True)
        immutable = ("identity", "provider", "connection", "context", "namespace", "binding")
        if prior and any(prior[key] != value[key] for key in immutable) and any(
                item["profile"]["id"] == prior["id"] for operation in self.records.all() for item in operation["targets"]):
            raise Failure("container_busy", "Remove operation receipts before changing this connection.", 409)
        if any(item["id"] != value["id"] and item["node_id"] == node_id and all(item[key] == value[key] for key in immutable)
               for item in self.records.profiles()):
            raise Failure("container_profile_exists", "This container connection is already registered.", 409)
        check()
        self.records.save_profile(value)
        self.service.store.audit("container.profile", value["id"], actor=actor)
        return value

    def profiles(self, actor):
        values = []
        for value in self.records.profiles():
            try:
                self.service.authorize(actor, "nodes:read", value["node_id"])
                self.service.authorize(actor, "container:read", value["node_id"])
                values.append(value)
            except Failure:
                continue
        return values

    async def remove_profile(self, actor, profile_id):
        async with self.admission:
            profile = self.records.profile(profile_id)
            self.service.live()
            self.service.authorize(actor, "nodes:write", profile["node_id"])
            self.service.authorize(actor, "container:read", profile["node_id"])
            if any(item["profile"]["id"] == profile_id for value in self.records.all() for item in value["targets"]):
                raise Failure("container_history", "Remove this profile's operation receipts before removing the profile.", 409)
            self.records.remove_profile(profile_id)
            self.resources = {key: item for key, item in self.resources.items() if item["profile"]["id"] != profile_id}
            self.service.store.audit("container.profile.remove", profile_id, actor=actor)
            return {"removed": True}

    def profile(self, identity):
        value = self.records.profile(identity)
        node = self.service.store.node(value["node_id"])
        if not value["enabled"] or value["identity"] != node_identity(node):
            raise Failure("container_profile_changed", "The container profile is disabled or its enrolled identity changed.", 409)
        return node, value

    def guard(self, actor, digest, node_id, capability, profile, check, recovery=False):
        def current():
            check()
            self.service.live()
            capabilities = list(dict.fromkeys(("container:read", capability)))
            self.service.policies.check_many(self.service.auth.current(actor),
                [(scope, node_id, None) for scope in ("nodes:read", *capabilities)])
            self.service.modules.require_many(digest, [(scope, [node_id]) for scope in capabilities])
            _, latest = self.profile(profile["id"])
            keys = set(profile) - ({"revision", "enabled", "version"} if recovery else set())
            if any(latest[key] != profile[key] for key in keys):
                raise Failure("container_profile_changed", "The registered container connection changed.", 409)
        current()
        return current

    def remember(self, profile, value):
        now = time.time()
        self.resources = {key: item for key, item in self.resources.items() if item["expires_at"] > now}
        for row in value["results"]:
            pointer = row.get("data", {}).get("resource") or row["resource"]
            identity = spec.resource(profile["id"], pointer)
            if identity not in self.resources and len(self.resources) >= 4096:
                self.resources.pop(next(iter(self.resources)))
            self.resources[identity] = {"resource": copy.deepcopy(pointer), "profile": copy.deepcopy(profile), "expires_at": now + 600}
            row.update(resource_id=identity, profile_id=profile["id"], provider=profile["provider"])

    def groups(self, node_ids, resource_ids):
        if not isinstance(resource_ids, list) or not 1 <= len(resource_ids) <= 64 or any(not isinstance(item, str) for item in resource_ids) or len(set(resource_ids)) != len(resource_ids):
            raise Failure("container_selection", "Select one to 64 distinct workloads.")
        grouped: dict[str, dict] = {}
        for identity in resource_ids:
            profile_id, _, _ = spec.resource_parts(identity)
            cached = self.resources.get(identity)
            if cached is None or cached["expires_at"] <= time.time():
                raise Failure("container_refresh", "Refresh inventory before selecting this workload.", 409)
            node, profile = self.profile(profile_id)
            if profile["node_id"] not in node_ids:
                raise Failure("container_target_denied", "The workload is outside the selected systems.", 403)
            if any(cached["profile"][key] != profile[key] for key in ("binding", "identity", "provider", "connection", "context", "namespace")):
                raise Failure("container_refresh", "Refresh inventory after the connection changes.", 409)
            group = grouped.setdefault(profile_id, {"node": node, "profile": profile, "resources": []})
            group["resources"].append(copy.deepcopy(cached["resource"]))
        return grouped

    async def read(self, actor, call):
        action = call.primitive.rsplit(".", 1)[1]
        if action == "list":
            spec.fields(call.parameters, set(), {"provider", "kind", "offset", "limit"})
            provider = call.parameters.get("provider", "all")
            kind = call.parameters.get("kind", "all")
            if provider not in spec.PROVIDERS | {"all"} or kind not in spec.KINDS | {"all"}:
                raise ValueError("Invalid provider or workload kind.")
            profiles = [item for item in self.records.profiles() if item["enabled"] and item["node_id"] in call.target_ids
                        and provider in {"all", item["provider"]}]
            limit = max(1, min(64, spec.integer(call.parameters.get("limit", 128), 1, 256) // max(1, len(profiles))))
            parameters = {"kind": kind, "offset": spec.integer(call.parameters.get("offset", 0), 0, 4096), "limit": limit}
            groups = {item["id"]: {"profile": item} for item in profiles}
        else:
            spec.fields(call.parameters, {"resource_ids"}, {"tail", "byte_limit", "container"} if action == "logs" else set())
            groups = self.groups(call.target_ids, call.parameters["resource_ids"])
            parameters = {}
            if action == "logs":
                parameters = {"tail": spec.integer(call.parameters.get("tail", 100), 1, 200),
                    "byte_limit": min(spec.integer(call.parameters.get("byte_limit", 16384), 1, 65536), 262144 // len(call.parameters["resource_ids"])),
                    "container": spec.text(call.parameters.get("container", ""), 63, empty=True)}
        async def one(group):
            profile = group["profile"]
            try:
                node, _ = self.profile(profile["id"])
                guard = self.guard(actor, call.package_digest, node["id"], "container:read", profile, call.check)
                if action == "logs":
                    guard = self.guard(actor, call.package_digest, node["id"], "container:logs", profile, guard)
                params = parameters if action == "list" else {**parameters, "resources": group["resources"]}
                result = await self.transport.request(node, profile, action, params, guard)
                self.remember(profile, result)
                return {"node_id": node["id"], "profile_id": profile["id"], "provider": profile["provider"], "data": result}
            except Failure as exc:
                return {"node_id": profile["node_id"], "profile_id": profile["id"], "error": spec.error(exc.code, exc.message)}
        results = await asyncio.gather(*(one(group) for group in groups.values()))
        call.check()
        for result in results:
            if "data" not in result:
                continue
            try:
                profile = groups[result["profile_id"]]["profile"]
                self.guard(actor, call.package_digest, result["node_id"], "container:read", profile, call.check)
                if action == "logs":
                    self.guard(actor, call.package_digest, result["node_id"], "container:logs", profile, call.check)
            except Failure as exc:
                result.pop("data")
                result["error"] = spec.error(exc.code, exc.message)
        output = []
        for node_id in call.target_ids:
            values = [item for item in results if item["node_id"] == node_id]
            filtered = action == "list" and provider != "all" and any(
                item["enabled"] and item["node_id"] == node_id for item in self.records.profiles())
            output.append({"target": node_id, "data": {"profiles": values}} if values or filtered else {
                "target": node_id, "error": spec.error("container_profile_missing", "No enabled container profile matches this system and provider.")})
        return output

    async def broker(self, actor, call, instance_id):
        try:
            async with asyncio.timeout(8):
                return await self._broker(actor, call, instance_id)
        except TimeoutError as exc:
            raise Failure("container_timeout", "The container read exceeded eight seconds. Refresh the data before another action.", 504) from exc

    async def _broker(self, actor, call, instance_id):
        capability = PRIMITIVES.get(call.primitive)
        if capability is None or capability not in call.action_capabilities or (capability != "container:read" and "container:read" not in call.action_capabilities):
            raise Failure("module_primitive_denied", "The container primitive is not permitted.", 403)
        try:
            if call.primitive in {"container.list", "container.status", "container.logs"}:
                return await self.read(actor, call)
            if call.primitive == "container.preview":
                value = await self.preview(actor, call.package_digest, instance_id, list(call.target_ids), call.parameters, call.check)
                return [{"target": target, "data": value if index == 0 else {**value, "workloads": []}} for index, target in enumerate(call.target_ids)]
            spec.fields(call.parameters, {"operation_id"})
            value = self.records.get(call.parameters["operation_id"])
            if value["package_digest"] != call.package_digest or value["instance_id"] != instance_id or any(item["node_id"] not in call.target_ids for item in value["targets"]):
                raise Failure("container_target_denied", "The operation is outside this module instance.", 403)
            result = await self.operation(actor, value["id"], call.check)
            return [{"target": target, "data": {"operation": result if index == 0 else None}} for index, target in enumerate(call.target_ids)]
        except (ValueError, KeyError, TypeError) as exc:
            raise Failure("container_invalid", "The container request is invalid.") from exc
