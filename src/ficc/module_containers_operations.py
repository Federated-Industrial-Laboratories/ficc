# SPDX-License-Identifier: Apache-2.0
"""Require frozen host confirmation and retain non-replayed container outcomes."""

import asyncio
import copy
import secrets
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ficc_node import container_spec as spec

from .errors import Failure
from .module_containers_store import Records, intent
from .providers.containers import Transport

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
    def effect(action, replicas):
        if action == "stop":
            return "Stop selected containers. The provider allows 10 seconds to exit, then forces them to stop. Other clients can change the state during this request."
        if action == "scale":
            return f"Set desired replicas to {replicas}. Pod readiness can change after this request completes."
        return "Start the selected existing containers with their saved configuration. Other clients can change the state during this request."

    async def preview(self, actor, digest, instance_id, node_ids, parameters, check):
        spec.fields(parameters, {"action", "resource_ids"}, {"replicas"})
        action, replicas = parameters["action"], parameters.get("replicas")
        if action not in spec.ACTIONS or action != "scale" and replicas is not None:
            raise Failure("container_action", "Select start, stop or a replica count.")
        if action == "scale":
            spec.integer(replicas, 0, 64)
        self.previews = {key: item for key, item in self.previews.items() if item["expires_at"] > time.time()}
        if len(self.previews) + self.preview_pending >= 64:
            raise Failure("container_capacity", "The container confirmation limit is full.", 429)
        self.preview_pending += 1
        try:
            groups = self.groups(node_ids, parameters["resource_ids"])
            async def one(group):
                node, profile = group["node"], group["profile"]
                guard = self.guard(actor, digest, node["id"], "container:power", profile, check)
                guard = self.guard(actor, digest, node["id"], "container:read", profile, guard)
                response = await self.transport.request(node, profile, "status", {"resources": group["resources"]}, guard)
                targets = []
                for row in response["results"]:
                    if "error" in row:
                        raise Failure(row["error"]["code"], row["error"]["message"], 409)
                    data = row["data"]
                    valid = ((action == "start" and data["resource"]["kind"] == "container" and data["state"] in {"created", "exited", "stopped"})
                             or (action == "stop" and data["resource"]["kind"] == "container" and data["state"] == "running")
                             or (action == "scale" and data["resource"]["kind"] in {"deployment", "statefulset"}))
                    if not valid:
                        raise Failure("container_state", "A selected workload cannot perform this action in its current state.", 409)
                    targets.append({"node_id": node["id"], "profile": copy.deepcopy(profile), "resource_id": spec.resource(profile["id"], data["resource"]),
                                    "expected": {key: data[key] for key in ("resource", "state", "revision", "definition", "replicas")}, "state": "queued"})
                return targets
            targets = [target for batch in await asyncio.gather(*(one(group) for group in groups.values())) for target in batch]
            order = {identity: index for index, identity in enumerate(parameters["resource_ids"])}
            targets.sort(key=lambda item: order[item["resource_id"]])
            check()
            value = {"id": secrets.token_hex(16), "actor": actor, "package_digest": digest, "instance_id": instance_id,
                     "action": action, "replicas": replicas, "targets": targets, "expires_at": time.time() + 120, "check": check}
            self.authority(actor, value, "container:power", check)
            self.previews[value["id"]] = value
            return self.public_preview(value)
        finally:
            self.preview_pending -= 1

    def public_preview(self, value):
        return {"preview_id": value["id"], "expires_at": value["expires_at"], "action": value["action"], "replicas": value["replicas"],
                "effect": self.effect(value["action"], value["replicas"]), "workloads": [{"node_id": item["node_id"], "resource_id": item["resource_id"],
                    "provider": item["profile"]["provider"], **item["expected"]["resource"], "state": item["expected"]["state"],
                    "replicas": item["expected"]["replicas"]} for item in value["targets"]]}

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
            if capability != "container:read":
                self.service.authorize(actor, "container:read", item["node_id"])
                self.service.modules.require(value["package_digest"], "container:read", [item["node_id"]])

    def preview_for_confirmation(self, actor, preview_id, check):
        check()
        value = self.previews.get(preview_id)
        if value is None or value["expires_at"] <= time.time() or value["actor"] != actor:
            raise Failure("container_preview_expired", "The container preview expired or belongs to another caller.", 409)
        value["check"]()
        self.authority(actor, value, "container:power", check)
        self.authority(actor, value, "container:read", check)
        return self.public_preview(value)

    async def commit(self, actor, preview_id, key, check):
        if len(self.dispatches) >= 64:
            raise Failure("container_busy", "The container dispatch queue is full.", 429)
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
            raise Failure("container_key", "Use an idempotency key of 16 to 128 printable ASCII characters.")
        async with self.admission:
            previous = self.records.existing(actor, key)
            if previous:
                if previous["preview_id"] != preview_id:
                    raise Failure("container_idempotency", "This idempotency key belongs to another preview.", 409)
                self.local_authority(actor, previous, "container:power", check)
                return self.public_operation(previous)
            self.preview_for_confirmation(actor, preview_id, check)
            preview = self.previews[preview_id]
            targets = copy.deepcopy(preview["targets"])
            selected = {(item["profile"]["binding"], item["expected"]["resource"]["id"]) for item in targets}
            if any((target["profile"]["binding"], target["expected"]["resource"]["id"]) in selected and target["state"] not in spec.TERMINAL
                   for value in self.records.all() for target in value["targets"]):
                raise Failure("container_busy", "A selected workload has an unfinished or unknown operation.", 409)
            now = time.time()
            value = {"id": secrets.token_hex(16), "actor": actor, "key": key, "preview_id": preview_id,
                     "package_digest": preview["package_digest"], "instance_id": preview["instance_id"], "controller": self.controller,
                     "action": preview["action"], "replicas": preview["replicas"], "created_at": now, "updated_at": now, "targets": targets}
            value["digest"] = spec.digest(intent(value))
            self.records.insert(value)
            self.previews.pop(preview_id)
            self.inflight.add(value["id"])
            self.service.store.audit("container." + value["action"], value["id"], actor=actor)
        def current():
            check()
            preview["check"]()
        async def one(items):
            profile = items[0]["profile"]
            try:
                node, _ = self.profile(profile["id"])
                guard = self.guard(actor, value["package_digest"], node["id"], "container:power", profile, current)
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
                    item["error"] = spec.error("container_outcome_unknown" if item["state"] == "unknown" else "container_not_dispatched",
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
            self.authority(actor, value, "container:power", current)
            return self.public_operation(value)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for item in value["targets"]:
                if item["state"] == "queued":
                    item.update(state="refused", error=spec.error("container_not_dispatched", "The controller stopped before dispatch."))
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
                "intent": {"action": value["action"], "replicas": value["replicas"], "expected": [item["expected"] for item in items]}}

    @staticmethod
    def public_operation(value):
        return {"id": value["id"], "action": value["action"], "replicas": value["replicas"], "instance_id": value["instance_id"],
                "created_at": value["created_at"], "updated_at": value["updated_at"],
                "cleanup": None if "cleanup" not in value else {"acknowledged": len(value["cleanup"]),
                    "total": len({item["profile"]["id"] for item in value["targets"]})},
                "targets": [{key: item[key] for key in ("node_id", "resource_id", "state", "error", "observed", "observed_at") if key in item}
                            for item in value["targets"]]}

    async def operation(self, actor, operation_id, check):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "container:read", check)
            if value["id"] in self.inflight or "cleanup" in value:
                return self.public_operation(value)
            for item in value["targets"]:
                if item["state"] in {"queued", "dispatching"}:
                    item["state"] = "unknown"
            async def one(items):
                profile = items[0]["profile"]
                node, _ = self.profile(profile["id"])
                guard = self.guard(actor, value["package_digest"], node["id"], "container:read", profile, check, recovery=True)
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
                    item["observed"] = {key: data[key] for key in ("state", "replicas", "ready")}
                    item["observed_at"] = time.time()
                    matches = (data["replicas"] == value["replicas"] if value["action"] == "scale" else data["state"] in (
                        {"running"} if value["action"] == "start" else {"exited", "stopped"}))
                    if item["state"] == "accepted" and matches:
                        item["state"] = "observed"
            try:
                results = await asyncio.gather(*(one(items) for items in self.operation_groups(value).values()), return_exceptions=True)
                for result in results:
                    if isinstance(result, BaseException) and not isinstance(result, Failure):
                        raise result
                self.local_authority(actor, value, "container:read", check)
            finally:
                self.records.save(value)
            return self.public_operation(value)

    async def resolve(self, actor, operation_id, resource_ids, check):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "container:power", check)
            self.local_authority(actor, value, "container:read", check)
            if value["id"] in self.inflight:
                raise Failure("container_busy", "This operation is still dispatching.", 409)
            if not isinstance(resource_ids, list) or not 1 <= len(resource_ids) <= 64 or any(not isinstance(item, str) for item in resource_ids) or len(set(resource_ids)) != len(resource_ids):
                raise Failure("container_selection", "Select distinct unknown workloads from this operation.")
            selected = [item for item in value["targets"] if item["resource_id"] in resource_ids]
            if len(selected) != len(resource_ids) or any(item["state"] not in {"unknown", "accepted"} for item in selected):
                raise Failure("container_state", "Only unknown or accepted outcomes can be explicitly resolved.", 409)
            for items in self.operation_groups({"targets": selected}).values():
                if not any(item["state"] == "accepted" for item in items):
                    continue
                profile = items[0]["profile"]
                node, _ = self.profile(profile["id"])
                guard = self.guard(actor, value["package_digest"], node["id"], "container:read", profile, check, recovery=True)
                response = await self.transport.request(node, profile, "status", {"resources": [item["expected"]["resource"] for item in items]}, guard)
                for item, row in zip(items, response["results"], strict=True):
                    if "data" not in row:
                        raise Failure("container_observation", "Read the current workload state before resolving an accepted action.", 409)
                    item["observed"] = {key: row["data"][key] for key in ("state", "replicas", "ready")}
                    item["observed_at"] = time.time()
            for item in selected:
                item.update(state="resolved", error=spec.error("container_owner_resolved", "The owner closed this outcome. This does not establish the action's effect."))
            self.local_authority(actor, value, "container:power", check)
            self.local_authority(actor, value, "container:read", check)
            self.records.save(value)
            self.service.store.audit("container.resolve", value["id"], actor=actor)
            return self.public_operation(value)

    async def forget(self, actor, operation_id, check):
        async with self.admission:
            value = self.records.get(operation_id)
            self.local_authority(actor, value, "container:power", check)
            if value["id"] in self.inflight or any(item["state"] not in spec.TERMINAL for item in value["targets"]):
                raise Failure("container_unresolved", "Observe or explicitly resolve every outcome before removing its receipt.", 409)
            value.setdefault("cleanup", [])
            self.records.save(value)
            async def one(profile_id, items):
                if profile_id in value["cleanup"]:
                    return
                profile = items[0]["profile"]
                node, _ = self.profile(profile_id)
                guard = self.guard(actor, value["package_digest"], node["id"], "container:power", profile, check, recovery=True)
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
                self.local_authority(actor, value, "container:power", check)
                self.records.remove(operation_id)
                self.service.store.audit("container.receipt.remove", operation_id, actor=actor)
                return {"removed": True}
            except (TimeoutError, Failure) as exc:
                raise Failure("container_cleanup_pending", "Some node receipts were not acknowledged. Retry receipt removal. No workloads were deleted.", 409) from exc
