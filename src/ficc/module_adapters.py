# SPDX-License-Identifier: Apache-2.0
"""Admit exact provider packages to explicit immutable endpoint account bindings."""

import asyncio
import secrets

from .errors import Failure
from .module_adapter_store import Records
from .module_adapter_store import profile as validate_profile
from .modules.adapter_manifest import ADMIN, ROLE
from .modules.adapter_protocol import Conversation, identity
from .modules.adapter_vm_protocol import result as vm_result
from .modules.validation import digest as valid_digest
from .modules.validation import dumps, loads


class Adapters:
    def __init__(self, service, *, windows=None, transport=None):
        self.service = service
        self.records = Records(service.store)
        if transport is None:
            from .providers.adapter_transport import EndpointTransport
            transport = EndpointTransport(service, windows=windows)
        self.transport = transport
        self.admission = asyncio.Lock()
        self.execution = asyncio.Semaphore(4)
        self.active: dict[asyncio.Task, tuple[str, str]] = {}

    def authorize(self, actor, endpoint_kind, endpoint_id, scope):
        self.service.live()
        self.service.authorize(actor, scope, endpoint_id)
        self.service.authorize(actor, "nodes:read", endpoint_id)

    def package(self, digest):
        valid_digest(digest)
        current = self.service.modules.get(digest)
        if current["manifest"].get("role") != ROLE:
            raise Failure("adapter_role_required", "Choose an installed provider adapter package.", 409)
        self.service.modules.verify(digest)
        return current

    def profile(self, profile_id, *, require_enabled=True):
        value = self.records.profile(profile_id)
        endpoint = self.transport.endpoint(value["endpoint_kind"], value["endpoint_id"])
        if (endpoint["revision"] != value["endpoint_revision"]
                or endpoint["machine_identity"] != value["machine_identity"]):
            raise Failure("adapter_endpoint_changed", "Register a new profile for the changed endpoint.", 409)
        if not endpoint["enabled"] or require_enabled and not value["enabled"]:
            raise Failure("adapter_disabled", "The provider profile or endpoint is disabled.", 409)
        return value

    def public(self, value):
        package = self.service.modules.get(value["digest"])
        allowed = package["enabled"] and any(grant["capability"] == ADMIN and value["id"] in grant["target_ids"]
                                             for grant in package["grants"])
        diagnostic = None
        try:
            self.profile(value["id"])
            if not allowed:
                raise Failure("adapter_grant_required", "Grant administration of this provider account before use.", 409)
        except Failure as exc:
            diagnostic = {"code": exc.code, "message": exc.message}
        return {**value, "admin_granted": bool(allowed), "ready": diagnostic is None, "diagnostic": diagnostic,
                "account_authority": "provider-administration",
                "display_name": package["manifest"].get("display_name", package["manifest"]["id"])}

    def profiles(self, actor):
        result = []
        for value in self.records.profiles():
            try:
                self.authorize(actor, value["endpoint_kind"], value["endpoint_id"], "vm:read")
                result.append(self.public(value))
            except Failure:
                continue
        return result

    async def bindings(self, actor, endpoint_kind, endpoint_id, check=lambda: None):
        self.authorize(actor, endpoint_kind, endpoint_id, "providers:write")
        def current():
            check()
            self.authorize(actor, endpoint_kind, endpoint_id, "providers:write")
        return await self.transport.bindings(endpoint_kind, endpoint_id, current)

    async def register_binding(self, actor, endpoint_kind, endpoint_id, parameters, check=lambda: None):
        self.authorize(actor, endpoint_kind, endpoint_id, "providers:write")
        def current():
            check()
            self.authorize(actor, endpoint_kind, endpoint_id, "providers:write")
        value = await self.transport.register_binding(endpoint_kind, endpoint_id, parameters, current)
        self.service.store.audit("adapter.binding", value["id"], actor=actor)
        return value

    async def create(self, actor, digest, endpoint_kind, endpoint_id, transport_binding_id, check=lambda: None):
        async with self.admission:
            if endpoint_kind not in ("linux-ssh", "windows"):
                raise Failure("adapter_endpoint_invalid", "Choose an enrolled SSH or Windows endpoint.")
            identity(endpoint_id)
            identity(transport_binding_id)
            self.authorize(actor, endpoint_kind, endpoint_id, "providers:write")
            current = self.package(digest)
            manifest = current["manifest"]["adapter"]
            expected = ("enrolled-node", "local-ipc") if endpoint_kind == "linux-ssh" else ("controller", "winrm-jea")
            if (manifest["execution"], manifest["transport"]) != expected:
                raise Failure("adapter_transport_mismatch", "The adapter does not support this endpoint type.", 409)
            endpoint = self.transport.endpoint(endpoint_kind, endpoint_id)
            if not endpoint["enabled"]:
                raise Failure("adapter_disabled", "Enable the enrolled endpoint before creating its profile.", 409)
            await self.transport.validate_binding(endpoint_kind, endpoint_id, transport_binding_id, check)
            check()
            self.authorize(actor, endpoint_kind, endpoint_id, "providers:write")
            if self.transport.endpoint(endpoint_kind, endpoint_id) != endpoint:
                raise Failure("adapter_endpoint_changed", "The endpoint changed during profile registration.", 409)
            value = {"id": secrets.token_hex(16), "digest": digest, "endpoint_kind": endpoint_kind,
                "endpoint_id": endpoint_id, "endpoint_revision": endpoint["revision"],
                "machine_identity": endpoint["machine_identity"], "transport_binding_id": transport_binding_id,
                "consistency": manifest["consistency"], "revision": 1, "enabled": False}
            validate_profile(value)
            self.records.save_profile(value)
            self.service.store.audit("adapter.profile", value["id"], actor=actor)
            return self.public(value)

    def _grants(self, digest, profile_id, add):
        current = self.service.modules.get(digest)
        selected = {target for grant in current["grants"] if grant["capability"] == ADMIN for target in grant["target_ids"]}
        selected.discard(profile_id)
        if add:
            selected.add(profile_id)
        grants = [{"capability": ADMIN, "target_ids": sorted(selected)}] if selected else []
        return self.service.modules.set_enabled(digest, bool(selected), grants, sandbox_ready=True)

    async def grant(self, actor, profile_id, expected_revision, *, confirmed=False, check=lambda: None):
        async with self.admission:
            value = self.profile(profile_id, require_enabled=False)
            self.authorize(actor, value["endpoint_kind"], value["endpoint_id"], "providers:write")
            if confirmed is not True:
                raise Failure("adapter_confirmation_required", "Confirm administration of this provider account.", 409)
            if type(expected_revision) is not int or expected_revision != value["revision"]:
                raise Failure("adapter_profile_changed", "Read the current provider profile before granting access.", 409)
            package = self.package(value["digest"])
            for other in self.service.modules.list():
                if (other["digest"] != value["digest"] and other["enabled"]
                        and other["manifest"]["id"] == package["manifest"]["id"]
                        and any(item["digest"] == other["digest"] for item in self.records.profiles())):
                    raise Failure("adapter_retained", "Remove the prior adapter profiles and receipts before changing its version.", 409)
            await self.transport.qualify(value, package["manifest"], check)
            check()
            self.authorize(actor, value["endpoint_kind"], value["endpoint_id"], "providers:write")
            self._grants(value["digest"], profile_id, True)
            try:
                def current():
                    check()
                    self.authorize(actor, value["endpoint_kind"], value["endpoint_id"], "providers:write")
                result = await self.execute(value, "probe", "probe", [], {}, current, allow_disabled=True)
                provider = result["provider"]
                value = {**value, "provider": provider, "enabled": True, "revision": value["revision"] + 1}
                self.records.save_profile(value)
            except BaseException:
                self._grants(value["digest"], profile_id, False)
                self.records.save_profile({**self.records.profile(profile_id), "enabled": False,
                                           "revision": self.records.profile(profile_id)["revision"] + 1})
                raise
            self.service.store.audit("adapter.grant", profile_id, actor=actor)
            return self.public(value)

    async def revoke(self, actor, profile_id):
        async with self.admission:
            value = self.records.profile(profile_id)
            self.service.live()
            self.service.authorize(actor, "providers:write", value["endpoint_id"])
            self._grants(value["digest"], profile_id, False)
            value = {**value, "enabled": False, "revision": value["revision"] + 1}
            self.records.save_profile(value)
            await self.stop(profile_id=profile_id)
            self.service.store.audit("adapter.revoke", profile_id, actor=actor)
            return self.public(value)

    async def remove(self, actor, profile_id):
        value = self.records.profile(profile_id)
        self.service.live()
        self.service.authorize(actor, "providers:write", value["endpoint_id"])
        if any(target["profile"]["id"] == profile_id for value in self.records.all() for target in value["targets"]):
            raise Failure("adapter_history", "Remove this profile's operation receipts before its profile.", 409)
        await self.revoke(actor, profile_id)
        async with self.admission:
            self.records.remove_profile(profile_id)
            self.service.store.audit("adapter.profile.remove", profile_id, actor=actor)
            return {"removed": True}

    async def execute(self, selected, phase, action, resources, parameters, check, *,
                      intent=None, receipt=None, allow_disabled=False):
        selected, resources, parameters, intent, receipt = loads(dumps(
            [selected, resources, parameters, intent, receipt]))
        task = asyncio.create_task(self._execute(selected, phase, action, resources, parameters, check,
                                                intent, receipt, allow_disabled))
        return await task

    async def _execute(self, selected, phase, action, resources, parameters, check, intent, receipt, allow_disabled):
        task = asyncio.current_task()
        assert task is not None
        if len(self.active) >= 64:
            raise Failure("capacity", "The provider adapter request queue is full.", 409)
        self.active[task] = (selected["id"], selected["digest"])
        try:
            async with self.execution:
                return await self._run(selected, phase, action, resources, parameters, check, intent, receipt, allow_disabled)
        finally:
            self.active.pop(task, None)

    async def _run(self, selected, phase, action, resources, parameters, check, intent, receipt, allow_disabled):
        current = self.service.modules.acquire(selected["digest"])
        try:
            manifest = current["manifest"]
            if (manifest.get("role") != ROLE or manifest["adapter"]["consistency"] != selected["consistency"]
                    or phase != "probe" and action not in manifest["adapter"]["operations"]):
                raise Failure("adapter_action_denied", "The adapter does not declare this operation or consistency class.", 409)
            def guard():
                check()
                latest = self.profile(selected["id"], require_enabled=not allow_disabled)
                if latest != selected:
                    raise Failure("adapter_profile_changed", "The provider binding changed during this request.", 409)
                self.service.modules.check(selected["digest"], current["revision"])
                self.service.modules.require(selected["digest"], ADMIN, [selected["id"]])
            guard()
            value = {"id": selected["id"], "endpoint_id": selected["endpoint_id"],
                "endpoint_revision": selected["endpoint_revision"], "machine_identity": selected["machine_identity"],
                "consistency": selected["consistency"], "resources": resources, "parameters": parameters}
            if intent is not None:
                value["intent"] = intent
            if receipt is not None:
                value["receipt"] = receipt
            conversation = Conversation(selected["digest"], phase, action, [value], guard)
            result = await self.transport.execute(selected, current["manifest"], conversation, guard)
            guard()
            result = conversation.result(result)["results"][0]
            if "error" in result:
                raise Failure(result["error"]["code"], result["error"]["message"], 409)
            return vm_result(result["data"], phase, action, value)
        finally:
            self.service.modules.release(selected["digest"])

    async def stop(self, digest=None, *, profile_id=None):
        tasks = [task for task, (profile, package) in self.active.items()
                 if (digest is None or digest == package) and (profile_id is None or profile == profile_id)
                 and task is not asyncio.current_task()]
        for task in tasks:
            if not task.cancelling():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
