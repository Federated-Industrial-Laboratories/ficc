# SPDX-License-Identifier: Apache-2.0
"""Retain confirmed adapter intents and never repeat an uncertain provider dispatch."""

import asyncio
import copy
import hashlib
import secrets
import time
from typing import TYPE_CHECKING

from .errors import Failure
from .module_adapter_store import TERMINAL, intent
from .module_vm_operations import Operations
from .modules import adapter_protocol as spec
from .modules.adapter_vm_protocol import pending_task
from .modules.validation import dumps

if TYPE_CHECKING:
    from .module_adapters import Adapters


class AdapterOperations(Operations):
    terminal_states = TERMINAL
    adapters: "Adapters"
    tasks: set[asyncio.Task]

    @staticmethod
    def operation_groups(value):
        grouped: dict[str, list[dict]] = {}
        for target in value["targets"]:
            grouped.setdefault(target["profile"]["id"], []).append(target)
        return grouped

    @staticmethod
    def adapter_intent(value, items):
        return {"controller": value["controller"], "operation": value["id"], "digest": value["digest"],
                "targets": [{"id": item["resource"]["id"], "intent": item["adapter_intent"]} for item in items]}

    @staticmethod
    def public_preview(value):
        result = {**Operations.public_preview(value), "provider": "adapter"}
        for public, target in zip(result["vms"], value["targets"], strict=True):
            public.update(profile_id=target["profile"]["id"], consistency=target["profile"]["consistency"])
        return result

    @staticmethod
    def public_operation(value):
        result = {**Operations.public_operation(value), "provider": "adapter"}
        for public, target in zip(result["targets"], value["targets"], strict=True):
            public.update(profile_id=target["profile"]["id"], consistency=target["profile"]["consistency"])
        return result

    async def commit(self, actor, preview_id, key, check):
        spec.identity(preview_id)
        if not isinstance(key, str) or not 16 <= len(key) <= 128 or not key.isascii() or not key.isprintable():
            raise Failure("vm_invalid_key", "Use an idempotency key of 16 to 128 printable ASCII characters.")
        async with self.admission:
            previous = self.records.existing(actor, key)
            if previous:
                if previous["preview_id"] != preview_id:
                    raise Failure("vm_idempotency_conflict", "This key belongs to a different preview.", 409)
                self.local_authority(actor, previous, "vm:power", check)
                return self.public_operation(previous)
            self.preview_for_confirmation(actor, preview_id, check)
            preview = self.previews[preview_id]
            targets = copy.deepcopy(preview["targets"])
            selected = {item["vm_id"] for item in targets}
            if any(target["vm_id"] in selected and target["state"] not in TERMINAL
                   for record in self.records.all() for target in record["targets"]):
                raise Failure("vm_busy", "A selected VM has an unfinished or unknown operation.", 409)
            for target in targets:
                target.pop("name")
            now = time.time()
            value = {"id": secrets.token_hex(16), "actor": actor, "key": key, "preview_id": preview_id,
                "package_digest": preview["package_digest"], "instance_id": preview["instance_id"],
                "controller": self.controller, "action": preview["action"], "created_at": now,
                "updated_at": now, "targets": targets}
            value["digest"] = hashlib.sha256(dumps(intent(value))).hexdigest()
            self.records.insert(value)
            self.previews.pop(preview_id)
            self.inflight.add(value["id"])
            self.service.store.audit("vm.adapter." + value["action"], value["id"], actor=actor)

        def current():
            check()
            preview["check"]()

        async def one(items):
            profile = items[0]["profile"]
            try:
                guard = self.guard(actor, value["package_digest"], profile["endpoint_id"], "vm:power", profile, current)
                def dispatch():
                    guard()
                    if all(item["state"] == "queued" for item in items):
                        for item in items:
                            item["state"] = "dispatching"
                        self.records.save(value)
                result = await self.adapters.execute(profile, "apply", value["action"],
                    [item["resource"] for item in items], {}, dispatch, intent=self.adapter_intent(value, items))
                for target, returned in zip(items, result["results"], strict=True):
                    self.accept(target, returned)
            except BaseException as exc:
                for item in items:
                    item["state"] = "refused" if item["state"] == "queued" else "unknown"
                    item["error"] = {"code": "vm_not_dispatched" if item["state"] == "refused" else "vm_outcome_unknown",
                        "message": "Dispatch did not occur." if item["state"] == "refused" else
                            "The provider dispatch outcome is unknown. This operation will not be repeated."}
                if not isinstance(exc, (Failure, asyncio.CancelledError)):
                    raise
            finally:
                self.records.save(value)

        tasks = [asyncio.create_task(one(items)) for items in self.operation_groups(value).values()]
        self.tasks.update(tasks)
        try:
            await asyncio.gather(*tasks)
            current()
            self.local_authority(actor, value, "vm:power", current)
            return self.public_operation(value)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.tasks.difference_update(tasks)
            self.inflight.discard(value["id"])
            self.records.save(value)

    @staticmethod
    def accept(target, returned):
        proof = copy.deepcopy(returned["receipt"])
        prior = target.get("adapter_receipt")
        if prior and prior["token"] and not prior["completed"]:
            if not proof["token"] or proof["token"] != prior["token"]:
                raise Failure("adapter_task_changed", "The provider task identity changed during observation.", 502)
        target["adapter_receipt"] = proof
        target["state"] = proof["state"]
        target.pop("error", None)
        if "error" in returned:
            target["error"] = copy.deepcopy(returned["error"])
        if "observed_state" in returned:
            target["observed_state"], target["observed_at"] = returned["observed_state"], time.time()

    async def operation(self, actor, operation_id, check):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "vm:read", check)
            if operation_id in self.inflight or "cleanup" in value:
                return self.public_operation(value)
            async def one(items):
                pending = [item for item in items if item["state"] not in TERMINAL]
                if not pending:
                    return
                profile = self.adapters.profile(items[0]["profile"]["id"])
                guard = self.guard(actor, value["package_digest"], profile["endpoint_id"], "vm:read",
                                   items[0]["profile"], check, recovery=True)
                proof = {"targets": [{"id": item["resource"]["id"], "receipt": item.get("adapter_receipt")} for item in pending]}
                result = await self.adapters.execute(profile, "observe", value["action"],
                    [item["resource"] for item in pending], {}, guard, intent=self.adapter_intent(value, pending), receipt=proof)
                for item, returned in zip(pending, result["results"], strict=True):
                    self.accept(item, returned)
            try:
                outcomes = await asyncio.gather(*(one(items) for items in self.operation_groups(value).values()), return_exceptions=True)
                for outcome in outcomes:
                    if isinstance(outcome, BaseException) and not isinstance(outcome, Failure):
                        raise outcome
                self.local_authority(actor, value, "vm:read", check)
            finally:
                for item in value["targets"]:
                    if item["state"] in {"queued", "dispatching"}:
                        item["state"] = "unknown"
                self.records.save(value)
            return self.public_operation(value)

    async def resolve(self, actor, operation_id, vm_ids, check):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "vm:power", check)
            if operation_id in self.inflight:
                raise Failure("vm_busy", "The provider operation is still dispatching.", 409)
            if (not isinstance(vm_ids, list) or not 1 <= len(vm_ids) <= 64
                    or any(not isinstance(item, str) for item in vm_ids) or len(set(vm_ids)) != len(vm_ids)):
                raise Failure("vm_invalid_selection", "Select one to 64 distinct VM outcomes.")
            selected = [item for item in value["targets"] if item["vm_id"] in vm_ids]
            if len(selected) != len(vm_ids) or any(item["state"] not in {"unknown", "accepted"} for item in selected):
                raise Failure("vm_invalid_selection", "Select pending or unknown outcomes from this operation.")
            if any(pending_task(item.get("adapter_receipt")) for item in selected):
                raise Failure("adapter_task_active", "Read a completed provider task before resolving its outcome.", 409)
            accepted = {**value, "targets": [item for item in selected if item["state"] == "accepted"]}
            for items in self.operation_groups(accepted).values():
                profile = self.adapters.profile(items[0]["profile"]["id"])
                guard = self.guard(actor, value["package_digest"], profile["endpoint_id"], "vm:read",
                                   items[0]["profile"], check, recovery=True)
                status = await self.adapters.execute(profile, "status", "status", [item["resource"] for item in items], {}, guard)
                for item, returned in zip(items, status["results"], strict=True):
                    if "error" in returned:
                        raise Failure("vm_observation_unavailable", "Read current VM state before closing an acknowledged outcome.", 409)
                    item["observed_state"], item["observed_at"] = returned["data"]["resource"]["state"], time.time()
            self.local_authority(actor, value, "vm:power", check)
            for item in selected:
                item["state"] = "resolved"
                item["error"] = {"code": "vm_owner_resolved", "message":
                    "The owner closed this unknown outcome. This does not establish the action's effect."}
            self.records.save(value)
            self.service.store.audit("vm.adapter.resolve", operation_id, actor=actor)
            return self.public_operation(value)

    def orphaned(self, profile):
        try:
            current = self.adapters.transport.endpoint(profile["endpoint_kind"], profile["endpoint_id"])
        except Failure as exc:
            if exc.status == 404:
                return True
            raise
        return current["machine_identity"] != profile["machine_identity"]

    async def forget(self, actor, operation_id, check, *, acknowledge_orphans=False):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "vm:read", check)
            self.local_authority(actor, value, "vm:power", check)
            if operation_id in self.inflight or any(item["state"] not in TERMINAL for item in value["targets"]):
                raise Failure("vm_unresolved", "Observe or explicitly resolve every outcome before removing its receipt.", 409)
            groups = self.operation_groups(value)
            orphans = [profile_id for profile_id, items in groups.items()
                       if items[0]["profile"]["endpoint_kind"] == "linux-ssh" and self.orphaned(items[0]["profile"])]
            if orphans and acknowledge_orphans is not True:
                raise Failure("adapter_orphan_ack_required",
                    "Confirm local receipt removal. Unreachable node tombstones will remain and cannot execute an action.", 409)
            value.setdefault("cleanup", [])
            self.records.save(value)
            for profile_id, items in groups.items():
                if profile_id in value["cleanup"]:
                    continue
                if profile_id not in orphans:
                    try:
                        await self.adapters.transport.forget(items[0]["profile"], self.adapter_intent(value, items),
                            [{"id": item["resource"]["id"], "state": item["state"]} for item in items], check)
                    except Failure as exc:
                        raise Failure("vm_cleanup_pending", "Node receipt removal is pending. Retry without repeating the VM action.", 409) from exc
                value["cleanup"].append(profile_id)
                self.records.save(value)
            self.local_authority(actor, value, "vm:power", check)
            self.service.store.audit("vm.adapter.receipt.remove", operation_id, actor=actor)
            for profile_id in orphans:
                self.service.store.audit("vm.adapter.receipt.orphan",
                    value["controller"] + ":" + operation_id + ":" + profile_id, actor=actor)
            self.records.remove(operation_id)
            return {"removed": True, "orphaned_profiles": orphans}

    async def close(self):
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
