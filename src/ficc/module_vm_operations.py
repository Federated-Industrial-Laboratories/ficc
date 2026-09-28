# SPDX-License-Identifier: Apache-2.0
"""Require a frozen host confirmation before dispatching durable VM intents."""

import asyncio
import copy
import secrets
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ficc_node import vm_spec as spec

from .errors import Failure
from .module_vm_store import Records
from .providers.libvirt import Transport

if TYPE_CHECKING:
    from .service import Service

TERMINAL = spec.TERMINAL


class Operations(ABC):
    terminal_states = TERMINAL
    service: "Service"
    records: Records
    transport: Transport
    previews: dict[str, dict]
    preview_pending: int
    controller: str
    admission: asyncio.Lock
    inflight: set[str]

    @abstractmethod
    def guard(self, actor, digest, node_id, capability, profile, check, recovery=False):
        raise NotImplementedError

    @abstractmethod
    def profile(self, node_id):
        raise NotImplementedError

    @abstractmethod
    def groups(self, node_ids, vm_ids):
        raise NotImplementedError

    @staticmethod
    def resource_id(profile_id, domain_id):
        return f"libvirt-{profile_id}-{domain_id}"

    def accept_receipt(self, target, receipt):
        target["state"] = receipt["state"]
        if "error" in receipt:
            target["error"] = receipt["error"]

    def reconcile_receipt(self, target, receipt):
        if target["state"] in {"queued", "dispatching", "unknown"}:
            target.pop("error", None)
            self.accept_receipt(target, receipt)

    def observe_receipt(self, action, target, observed):
        if "data" in observed:
            target["observed_state"] = observed["data"]["state"]
            target["observed_at"] = time.time()
            desired = {"off"} if action == "shutdown" else {"running", "blocked", "paused"}
            if target["state"] == "accepted" and target["observed_state"] in desired:
                target["state"] = "observed"

    async def preview(self, actor, digest, instance_id, node_ids, parameters, check):
        spec.fields(parameters, {"action", "vm_ids"})
        action = parameters["action"]
        if action not in {"start", "shutdown"}:
            raise Failure("vm_action_denied", "Select start or graceful shutdown.")
        self.previews = {key: item for key, item in self.previews.items() if item["expires_at"] > time.time()}
        if len(self.previews) + self.preview_pending >= 64:
            raise Failure("vm_preview_capacity", "The VM confirmation preview limit is full.", 429)
        self.preview_pending += 1
        try:
            profiles, grouped = self.groups(node_ids, parameters["vm_ids"])
            targets = []

            async def one(node_id, ids):
                node, profile = profiles[node_id]
                guard = self.guard(actor, digest, node_id, "vm:power", profile, check)
                # Power previews include status, so read authority is required too.
                guard = self.guard(actor, digest, node_id, "vm:read", profile, guard)
                result = await self.transport.request(node, profile, "status", {"uuids": ids}, guard)
                selected = []
                for item in result["results"]:
                    if "error" in item:
                        raise Failure(item["error"]["code"], item["error"]["message"], 409)
                    data = item["data"]
                    allowed = {"start": {"off"}, "shutdown": {"running", "blocked", "paused"}}
                    if data["state"] not in allowed[action]:
                        raise Failure("vm_state_conflict", "A selected VM cannot perform this action in its current state.", 409)
                    selected.append({"node_id": node_id, "profile": profile,
                                     "vm_id": self.resource_id(profile["id"], item["uuid"]),
                                     "expected": {key: data[key] for key in ("uuid", "definition", "state")},
                                     "name": data["name"], "state": "queued"})
                return selected
            for batch in await asyncio.gather(*(one(node_id, ids) for node_id, ids in grouped.items())):
                targets.extend(batch)
            check()
            value = {"id": secrets.token_hex(16), "actor": actor, "package_digest": digest,
                     "instance_id": instance_id, "action": action, "targets": targets,
                     "expires_at": time.time() + 120, "check": check}
            self.previews[value["id"]] = value
            return self.public_preview(value)
        finally:
            self.preview_pending -= 1

    @staticmethod
    def public_preview(value):
        return {"preview_id": value["id"], "expires_at": value["expires_at"], "action": value["action"],
                "vms": [{"node_id": item["node_id"], "vm_id": item["vm_id"], "name": item["name"],
                         "state": item["expected"]["state"]} for item in value["targets"]]}

    def preview_for_confirmation(self, actor, preview_id, check):
        check()
        value = self.previews.get(preview_id)
        if value is None or value["expires_at"] <= time.time() or value["actor"] != actor:
            raise Failure("vm_preview_expired", "The VM preview expired or belongs to another caller.", 409)
        value["check"]()
        self.authority(actor, value, "vm:power", check)
        return self.public_preview(value)

    def authority(self, actor, value, capability, check):
        for target in value["targets"]:
            self.guard(actor, value["package_digest"], target["node_id"], capability, target["profile"], check)

    def local_authority(self, actor, value, capability, check):
        check()
        self.service.live()
        for target in value["targets"]:
            self.service.authorize(actor, "nodes:read", target["node_id"])
            self.service.authorize(actor, capability, target["node_id"])
            self.service.modules.require(value["package_digest"], capability, [target["node_id"]])

    async def commit(self, actor, preview_id, key, check):
        spec.identity(preview_id)
        if not isinstance(key, str) or not 16 <= len(key) <= 128 or not key.isascii() or not key.isprintable():
            raise Failure("vm_invalid_key", "Use an idempotency key of 16 to 128 printable ASCII characters.")
        async with self.admission:
            previous = self.records.existing(actor, key)
            if previous:
                if previous["preview_id"] != preview_id:
                    raise Failure("vm_idempotency_conflict", "This idempotency key belongs to a different preview.", 409)
                self.authority(actor, previous, "vm:power", check)
                return self.public_operation(previous)
            self.preview_for_confirmation(actor, preview_id, check)
            preview = self.previews[preview_id]
            targets = copy.deepcopy(preview["targets"])
            selected = {item["vm_id"] for item in targets}
            if any(target["vm_id"] in selected and target["state"] not in self.terminal_states
                   for value in self.records.all() for target in value["targets"]):
                raise Failure("vm_busy", "A selected VM has an unfinished or unknown operation.", 409)
            for target in targets:
                target.pop("name")
            now = time.time()
            value = {"id": secrets.token_hex(16), "actor": actor, "key": key,
                     "preview_id": preview_id, "package_digest": preview["package_digest"],
                     "instance_id": preview["instance_id"], "controller": self.controller,
                     "action": preview["action"], "created_at": now, "updated_at": now, "targets": targets}
            value["digest"] = spec.digest({key: value[key] for key in ("preview_id", "action", "targets")})
            self.records.insert(value)
            self.previews.pop(preview_id)
            self.inflight.add(value["id"])
            self.service.store.audit("vm." + value["action"], value["id"], actor=actor)

        def current():
            check()
            preview["check"]()

        grouped = self.operation_groups(value)

        async def one(node_id, items):
            profile = items[0]["profile"]
            try:
                node, _ = self.profile(node_id)
                guard = self.guard(actor, value["package_digest"], node_id, "vm:power", profile, current)

                def dispatch_check():
                    guard()
                    if all(item["state"] == "queued" for item in items):
                        for item in items:
                            item["state"] = "dispatching"
                        self.records.save(value)

                result = await self.transport.request(node, profile, "apply", self.receipt_parameters(value, items), dispatch_check)
                for target, receipt in zip(items, result["results"], strict=True):
                    self.accept_receipt(target, receipt)
            except (Failure, asyncio.CancelledError) as exc:
                for item in items:
                    item["state"] = "refused" if item["state"] == "queued" else "unknown"
                    reason = exc.message if isinstance(exc, Failure) else "The controller request was cancelled."
                    prefix = "Outcome unknown: " if item["state"] == "unknown" else "Not dispatched: "
                    item["error"] = {"code": "vm_outcome_unknown" if item["state"] == "unknown" else "vm_not_dispatched",
                                     "message": (prefix + reason)[:256]}
                raise
            finally:
                self.records.save(value)

        tasks = [asyncio.create_task(one(node_id, items)) for node_id, items in grouped.items()]
        try:
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, BaseException) and not isinstance(outcome, Failure):
                    raise outcome
            current()
            self.authority(actor, value, "vm:power", current)
            return self.public_operation(value)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for item in value["targets"]:
                if item["state"] == "queued":
                    item["state"] = "refused"
                    item["error"] = {"code": "vm_not_dispatched", "message": "The controller stopped before dispatch."}
            self.records.save(value)
            self.inflight.discard(value["id"])

    @staticmethod
    def operation_groups(value):
        grouped: dict[str, list[dict]] = {}
        for target in value["targets"]:
            grouped.setdefault(target["node_id"], []).append(target)
        return grouped

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
                "targets": [{key: item[key] for key in ("node_id", "vm_id", "state", "error", "observed_state", "observed_at")
                             if key in item} for item in value["targets"]]}

    async def operation(self, actor, operation_id, check):
        # Serialize read-modify-write reconciliation against admission and resolution.
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "vm:read", check)
            if value["id"] in self.inflight or "cleanup" in value:
                return self.public_operation(value)

            async def one(node_id, items):
                node, profile = self.profile(node_id)
                guard = self.guard(actor, value["package_digest"], node_id, "vm:read", items[0]["profile"], check, recovery=True)
                try:
                    receipt = await self.transport.request(node, profile, "receipt", self.receipt_parameters(value, items), guard)
                    for item, remote in zip(items, receipt["results"], strict=True):
                        self.reconcile_receipt(item, remote)
                except Failure:
                    for item in items:
                        if item["state"] in {"queued", "dispatching"}:
                            item["state"] = "unknown"
                status = await self.transport.request(node, profile, "status", {"uuids": [item["expected"]["uuid"] for item in items]}, guard)
                for item, observed in zip(items, status["results"], strict=True):
                    self.observe_receipt(value["action"], item, observed)

            try:
                outcomes = await asyncio.gather(*(one(node_id, items) for node_id, items in self.operation_groups(value).items()), return_exceptions=True)
                for outcome in outcomes:
                    if isinstance(outcome, BaseException) and not isinstance(outcome, Failure):
                        raise outcome
                check()
                self.local_authority(actor, value, "vm:read", check)
            finally:
                self.records.save(value)
            return self.public_operation(value)

    async def resolve(self, actor, operation_id, vm_ids, check):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "vm:power", check)
            if value["id"] in self.inflight:
                raise Failure("vm_busy", "The operation is still dispatching.", 409)
            if (not isinstance(vm_ids, list) or not vm_ids or len(vm_ids) > 64
                    or any(not isinstance(item, str) for item in vm_ids)
                    or len(set(vm_ids)) != len(vm_ids)
                    or set(vm_ids) - {item["vm_id"] for item in value["targets"]}):
                raise Failure("vm_invalid_selection", "Select unresolved targets from this operation.")
            selected = [item for item in value["targets"] if item["vm_id"] in vm_ids]
            if any(item["state"] not in {"unknown", "accepted"} for item in selected):
                raise Failure("vm_state_conflict", "Only pending or unknown outcomes can be explicitly resolved.", 409)
            accepted = {**value, "targets": [item for item in selected if item["state"] == "accepted"]}
            observations = []
            for node_id, items in self.operation_groups(accepted).items():
                node, _ = self.profile(node_id)
                guard = self.guard(actor, value["package_digest"], node_id, "vm:read", items[0]["profile"], check, recovery=True)
                result = await self.transport.request(node, items[0]["profile"], "status",
                    {"uuids": [item["expected"]["uuid"] for item in items]}, guard)
                for item, observed in zip(items, result["results"], strict=True):
                    if "error" in observed:
                        raise Failure("vm_observation_unavailable", "Read the current VM state before closing a pending outcome.", 409)
                    observations.append((item, observed["data"]["state"]))
            self.local_authority(actor, value, "vm:power", check)
            for item, state in observations:
                item["observed_state"], item["observed_at"] = state, time.time()
            for item in selected:
                item["state"] = "resolved"
                item["error"] = {"code": "vm_owner_resolved", "message": "The owner closed this pending or unknown outcome. This does not establish the action's effect."}
            check()
            self.records.save(value)
            self.service.store.audit("vm.resolve", value["id"], actor=actor)
            return self.public_operation(value)

    async def forget(self, actor, operation_id, check, *, acknowledge_orphans=False):
        if acknowledge_orphans:
            raise Failure("vm_cleanup_invalid", "This provider requires acknowledged node receipt removal.", 409)
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "vm:read", check)
            self.local_authority(actor, value, "vm:power", check)
            if value["id"] in self.inflight or any(item["state"] not in self.terminal_states for item in value["targets"]):
                raise Failure("vm_unresolved", "Observe or explicitly resolve every outcome before removing its receipt.", 409)
            value.setdefault("cleanup", [])
            self.records.save(value)

            async def one(node_id, items):
                profile = items[0]["profile"]
                if profile["id"] in value["cleanup"]:
                    return
                node, _ = self.profile(node_id)
                guard = self.guard(actor, value["package_digest"], node_id, "vm:power", profile, check, recovery=True)
                parameters = self.receipt_parameters(value, items)
                parameters["outcomes"] = [{"uuid": item["expected"]["uuid"], "state": item["state"]} for item in items]
                await self.transport.request(node, profile, "forget", parameters, guard)
                value["cleanup"].append(profile["id"])
                self.records.save(value)
            try:
                async with asyncio.timeout(25):
                    outcomes = await asyncio.gather(*(one(node_id, items) for node_id, items in self.operation_groups(value).items()), return_exceptions=True)
                for outcome in outcomes:
                    if isinstance(outcome, BaseException):
                        raise outcome
                self.local_authority(actor, value, "vm:read", check)
                self.local_authority(actor, value, "vm:power", check)
                self.records.remove(operation_id)
                self.service.store.audit("vm.receipt.remove", operation_id, actor=actor)
                return {"removed": True}
            except (TimeoutError, Failure) as exc:
                raise Failure("vm_cleanup_pending", "Some node receipts were not acknowledged. Retry receipt removal. No VMs were deleted.", 409) from exc
