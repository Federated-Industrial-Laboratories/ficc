# SPDX-License-Identifier: Apache-2.0
"""Require frozen host confirmation and retain non-replayed admin outcomes."""

import asyncio
import copy
import secrets
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ficc_node import admin_spec as spec

from .errors import Failure
from .module_admin_store import Records, intent
from .providers.admin import Transport

if TYPE_CHECKING:
    from .service import Service


class Operations(ABC):
    service: "Service"
    records: Records
    transport: Transport
    previews: dict[str, dict]
    preview_pending: int
    controller: str
    admission: asyncio.Lock
    inflight: set[str]
    dispatches: set[asyncio.Task]

    @abstractmethod
    def guard(self, actor, digest, node_id, capability, profile, check, recovery=False):
        raise NotImplementedError

    @abstractmethod
    def groups(self, node_ids, resource_ids):
        raise NotImplementedError

    @abstractmethod
    def profile(self, identity):
        raise NotImplementedError

    @staticmethod
    def effect(action):
        if action in spec.POWER:
            return ("Queue a normal " + action + ". Active work can stop. Current inhibitors and account policy apply. "
                    "An acknowledgement means queued, not complete. SSH loss does not establish the power state.")
        return ("Queue service " + action + ". Unit dependencies and configured stop timeouts apply; systemd can terminate processes. "
                "External changes can occur after the final state check. This action is not an atomic compare-and-change.")

    async def preview(self, actor, digest, instance_id, node_ids, parameters, check):
        spec.fields(parameters, {"action", "resource_ids"})
        action = parameters["action"]
        capability = spec.capability(action)
        self.previews = {key: item for key, item in self.previews.items() if item["expires_at"] > time.time()}
        if len(self.previews) + self.preview_pending >= 64:
            raise Failure("admin_capacity", "The admin confirmation limit is full.", 429)
        self.preview_pending += 1
        try:
            groups = self.groups(node_ids, parameters["resource_ids"])
            async def one(group):
                node, profile = group["node"], group["profile"]
                guard = self.guard(actor, digest, node["id"], capability, profile, check)
                guard = self.guard(actor, digest, node["id"], "admin:read", profile, guard)
                response = await self.transport.request(node, profile, "status", {"resources": group["resources"]}, guard)
                targets = []
                for row in response["results"]:
                    if "error" in row:
                        raise Failure(row["error"]["code"], row["error"]["message"], 409)
                    data = row["data"]
                    valid = ((action in spec.POWER and data["resource"]["kind"] == "system" and profile["manager"] == "system")
                             or (action == "start" and data["resource"]["kind"] == "service" and data["state"] in {"inactive", "failed"})
                             or (action in {"stop", "restart"} and data["resource"]["kind"] == "service" and data["state"] == "active"))
                    if not valid:
                        raise Failure("admin_state", "A selected resource cannot perform this action in its current state.", 409)
                    if action in spec.POWER and data.get("power", {}).get(action) != "yes":
                        access = data.get("power", {}).get(action, "unavailable")
                        message = ("This account requires interactive authentication for " + action + ". Configure noninteractive system policy and refresh."
                                   if access == "challenge" else "Power permission is unavailable. Check account policy, the login service and the current node helper.")
                        raise Failure("admin_power_denied", message, 403)
                    targets.append({"node_id": node["id"], "profile": copy.deepcopy(profile), "resource_id": spec.resource(profile["id"], data["resource"]),
                                    "expected": {key: data[key] for key in spec.EXPECTED}, "state": "queued"})
                return targets
            targets = [target for batch in await asyncio.gather(*(one(group) for group in groups.values())) for target in batch]
            if action in spec.POWER and len({item["profile"]["system_id"] for item in targets}) != len(targets):
                raise Failure("admin_selection", "Select each physical system once for a power action.", 409)
            order = {identity: index for index, identity in enumerate(parameters["resource_ids"])}
            targets.sort(key=lambda item: order[item["resource_id"]])
            check()
            value = {"id": secrets.token_hex(16), "actor": actor, "package_digest": digest, "instance_id": instance_id,
                     "action": action, "targets": targets, "expires_at": time.time() + 120, "check": check}
            self.authority(actor, value, spec.capability(value["action"]), check)
            self.previews[value["id"]] = value
            return self.public_preview(value)
        finally:
            self.preview_pending -= 1

    def public_preview(self, value):
        return {"preview_id": value["id"], "expires_at": value["expires_at"], "action": value["action"],
                "effect": self.effect(value["action"]), "resources": [{"node_id": item["node_id"], "resource_id": item["resource_id"],
                    "provider": item["profile"]["provider"], **item["expected"]["resource"], "state": item["expected"]["state"]} for item in value["targets"]]}

    def authority(self, actor, value, capability, check, recovery=False):
        for item in value["targets"]:
            self.guard(actor, value["package_digest"], item["node_id"], capability, item["profile"], check, recovery)

    def local_authority(self, actor, value, capability, check):
        check()
        self.service.live()
        for item in value["targets"]:
            self.service.authorize(actor, "nodes:read", item["node_id"])
            self.service.authorize(actor, capability, item["node_id"])
            self.service.modules.require(value["package_digest"], capability, [item["node_id"]])
            if capability != "admin:read":
                self.service.authorize(actor, "admin:read", item["node_id"])
                self.service.modules.require(value["package_digest"], "admin:read", [item["node_id"]])

    def preview_for_confirmation(self, actor, preview_id, check):
        check()
        value = self.previews.get(preview_id)
        if value is None or value["expires_at"] <= time.time() or value["actor"] != actor:
            raise Failure("admin_preview_expired", "The admin preview expired or belongs to another caller.", 409)
        value["check"]()
        self.authority(actor, value, spec.capability(value["action"]), check)
        self.authority(actor, value, "admin:read", check)
        return self.public_preview(value)

    async def commit(self, actor, preview_id, key, check):
        if len(self.dispatches) >= 64:
            raise Failure("admin_busy", "The admin dispatch queue is full.", 429)
        task = asyncio.create_task(self._commit(actor, preview_id, key, check))
        self.dispatches.add(task)
        def complete(done):
            self.dispatches.discard(done)
            if not done.cancelled():
                done.exception()
        task.add_done_callback(complete)
        return await asyncio.shield(task)

    async def close(self):
        tasks = list(self.dispatches)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _commit(self, actor, preview_id, key, check):
        spec.identity(preview_id)
        if not isinstance(key, str) or not 16 <= len(key) <= 128 or not key.isascii() or not key.isprintable():
            raise Failure("admin_key", "Use an idempotency key of 16 to 128 printable ASCII characters.")
        async with self.admission:
            previous = self.records.existing(actor, key)
            if previous:
                if previous["preview_id"] != preview_id:
                    raise Failure("admin_idempotency", "This idempotency key belongs to another preview.", 409)
                self.local_authority(actor, previous, spec.capability(previous["action"]), check)
                return self.public_operation(previous)
            self.preview_for_confirmation(actor, preview_id, check)
            preview = self.previews[preview_id]
            targets = copy.deepcopy(preview["targets"])
            selected = {(item["profile"]["binding"], item["expected"]["resource"]["id"]) for item in targets}
            if any((value["action"] in spec.POWER or preview["action"] in spec.POWER) and target["state"] not in spec.TERMINAL
                   and target["profile"]["system_id"] in {item["profile"]["system_id"] for item in targets}
                   for value in self.records.all() for target in value["targets"]):
                raise Failure("admin_busy", "A selected system has an unfinished administration action.", 409)
            if any((target["profile"]["binding"], target["expected"]["resource"]["id"]) in selected and target["state"] not in spec.TERMINAL
                   for value in self.records.all() for target in value["targets"]):
                raise Failure("admin_busy", "A selected resource has an unfinished or unknown operation.", 409)
            now = time.time()
            value = {"id": secrets.token_hex(16), "actor": actor, "key": key, "preview_id": preview_id,
                     "package_digest": preview["package_digest"], "instance_id": preview["instance_id"], "controller": self.controller,
                     "action": preview["action"], "created_at": now, "updated_at": now, "targets": targets}
            value["digest"] = spec.digest(intent(value))
            self.records.insert(value)
            self.previews.pop(preview_id)
            self.inflight.add(value["id"])
            self.service.store.audit("admin." + value["action"], value["id"], actor=actor)
        def current():
            check()
            preview["check"]()
        async def one(items):
            profile = items[0]["profile"]
            try:
                node, _ = self.profile(profile["id"])
                guard = self.guard(actor, value["package_digest"], node["id"], spec.capability(value["action"]), profile, current)
                def dispatch_check():
                    guard()
                    if all(item["state"] == "queued" for item in items):
                        for item in items:
                            item["state"] = "dispatching"
                        self.records.save(value)
                response = await self.transport.request(node, profile, "apply", self.receipt_parameters(value, items), dispatch_check)
                for item, row in zip(items, response["results"], strict=True):
                    item["state"] = row["state"]
                    if "error" in row:
                        item["error"] = row["error"]
            except (Failure, asyncio.CancelledError):
                for item in items:
                    item["state"] = "refused" if item["state"] == "queued" else "unknown"
                    item["error"] = spec.error("admin_outcome_unknown" if item["state"] == "unknown" else "admin_not_dispatched",
                                                "Dispatch was not confirmed. Inspect the operation before another action.")
                raise
            finally:
                self.records.save(value)
        tasks = [asyncio.create_task(one(items)) for items in self.operation_groups(value).values()]
        try:
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, BaseException) and not isinstance(outcome, Failure):
                    raise outcome
            current()
            self.authority(actor, value, spec.capability(value["action"]), current)
            return self.public_operation(value)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for item in value["targets"]:
                if item["state"] == "queued":
                    item.update(state="refused", error=spec.error("admin_not_dispatched", "The controller stopped before dispatch."))
            self.records.save(value)
            self.inflight.discard(value["id"])

    @staticmethod
    def operation_groups(value):
        groups: dict[str, list[dict]] = {}
        for item in value["targets"]:
            groups.setdefault(item["profile"]["id"], []).append(item)
        return groups

    @staticmethod
    def receipt_parameters(value, items):
        return {"controller": value["controller"], "operation": value["id"],
                "intent": {"action": value["action"], "expected": [item["expected"] for item in items]}}

    @staticmethod
    def public_operation(value):
        return {"id": value["id"], "action": value["action"], "instance_id": value["instance_id"],
                "created_at": value["created_at"], "updated_at": value["updated_at"],
                "cleanup": None if "cleanup" not in value else {"acknowledged": len(value["cleanup"]),
                    "total": len({item["profile"]["id"] for item in value["targets"]})},
                "targets": [{key: item[key] for key in ("node_id", "resource_id", "state", "error", "observed", "observed_at") if key in item}
                            for item in value["targets"]]}

    async def operation(self, actor, operation_id, check):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "admin:read", check)
            if value["id"] in self.inflight or "cleanup" in value:
                return self.public_operation(value)
            for item in value["targets"]:
                if item["state"] in {"queued", "dispatching"}:
                    item["state"] = "unknown"
            async def one(items):
                profile = items[0]["profile"]
                node, _ = self.profile(profile["id"])
                guard = self.guard(actor, value["package_digest"], node["id"], "admin:read", profile, check, recovery=True)
                try:
                    response = await self.transport.request(node, profile, "receipt", self.receipt_parameters(value, items), guard)
                    for item, row in zip(items, response["results"], strict=True):
                        if item["state"] in {"queued", "dispatching", "unknown"}:
                            item["state"] = row["state"]
                            item.pop("error", None)
                            if "error" in row:
                                item["error"] = row["error"]
                except Failure:
                    for item in items:
                        if item["state"] in {"queued", "dispatching"}:
                            item["state"] = "unknown"
                response = await self.transport.request(node, profile, "status", {"resources": [item["expected"]["resource"] for item in items]}, guard)
                for item, row in zip(items, response["results"], strict=True):
                    if "data" not in row:
                        continue
                    data = row["data"]
                    item["observed"] = {key: data[key] for key in ("state", "boot_id", "invocation")}
                    item["observed_at"] = time.time()
                    matches = (value["action"] not in spec.POWER and data["boot_id"] == item["expected"]["boot_id"]
                               and ((value["action"] == "stop" and data["state"] in {"inactive", "failed"})
                                    or value["action"] in {"start", "restart"} and data["state"] == "active"
                                    and data["invocation"] != item["expected"]["invocation"]))
                    if item["state"] == "accepted" and matches:
                        item["state"] = "observed"
            try:
                results = await asyncio.gather(*(one(items) for items in self.operation_groups(value).values()), return_exceptions=True)
                for result in results:
                    if isinstance(result, BaseException) and not isinstance(result, Failure):
                        raise result
                self.local_authority(actor, value, "admin:read", check)
            finally:
                self.records.save(value)
            return self.public_operation(value)

    async def resolve(self, actor, operation_id, resource_ids, check):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, spec.capability(value["action"]), check)
            self.local_authority(actor, value, "admin:read", check)
            if value["id"] in self.inflight:
                raise Failure("admin_busy", "This operation is still dispatching.", 409)
            if not isinstance(resource_ids, list) or not 1 <= len(resource_ids) <= 64 or any(not isinstance(item, str) for item in resource_ids) or len(set(resource_ids)) != len(resource_ids):
                raise Failure("admin_selection", "Select distinct unknown resources from this operation.")
            selected = [item for item in value["targets"] if item["resource_id"] in resource_ids]
            if len(selected) != len(resource_ids) or any(item["state"] not in {"unknown", "accepted"} for item in selected):
                raise Failure("admin_state", "Only unknown or accepted outcomes can be explicitly resolved.", 409)
            for items in self.operation_groups({"targets": selected}).values():
                if value["action"] in spec.POWER or not any(item["state"] == "accepted" for item in items):
                    continue
                profile = items[0]["profile"]
                node, _ = self.profile(profile["id"])
                guard = self.guard(actor, value["package_digest"], node["id"], "admin:read", profile, check, recovery=True)
                response = await self.transport.request(node, profile, "status", {"resources": [item["expected"]["resource"] for item in items]}, guard)
                for item, row in zip(items, response["results"], strict=True):
                    if "data" not in row:
                        raise Failure("admin_observation", "Read the current resource state before resolving an accepted action.", 409)
                    item["observed"] = {key: row["data"][key] for key in ("state", "boot_id", "invocation")}
                    item["observed_at"] = time.time()
            for item in selected:
                item.update(state="resolved", error=spec.error("admin_owner_resolved", "The owner closed this outcome. This does not establish the action's effect."))
            self.local_authority(actor, value, spec.capability(value["action"]), check)
            self.local_authority(actor, value, "admin:read", check)
            self.records.save(value)
            self.service.store.audit("admin.resolve", value["id"], actor=actor)
            return self.public_operation(value)

    async def forget(self, actor, operation_id, check):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, spec.capability(value["action"]), check)
            if value["id"] in self.inflight or any(item["state"] not in spec.TERMINAL for item in value["targets"]):
                raise Failure("admin_unresolved", "Observe or explicitly resolve every outcome before removing its receipt.", 409)
            value.setdefault("cleanup", [])
            self.records.save(value)
            async def one(profile_id, items):
                if profile_id in value["cleanup"]:
                    return
                profile = items[0]["profile"]
                node, _ = self.profile(profile_id)
                guard = self.guard(actor, value["package_digest"], node["id"], spec.capability(value["action"]), profile, check, recovery=True)
                parameters = self.receipt_parameters(value, items)
                parameters["outcomes"] = [{"resource": item["expected"]["resource"], "state": item["state"]} for item in items]
                await self.transport.request(node, profile, "forget", parameters, guard)
                value["cleanup"].append(profile_id)
                self.records.save(value)
            try:
                async with asyncio.timeout(25):
                    outcomes = await asyncio.gather(*(one(key, items) for key, items in self.operation_groups(value).items()), return_exceptions=True)
                for outcome in outcomes:
                    if isinstance(outcome, BaseException):
                        raise outcome
                self.local_authority(actor, value, spec.capability(value["action"]), check)
                self.records.remove(operation_id)
                self.service.store.audit("admin.receipt.remove", operation_id, actor=actor)
                return {"removed": True}
            except (TimeoutError, Failure) as exc:
                raise Failure("admin_cleanup_pending", "Some node receipts were not acknowledged. Retry receipt removal. No resources were deleted.", 409) from exc
