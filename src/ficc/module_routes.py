# SPDX-License-Identifier: Apache-2.0
"""Inspect package bytes before installation and check each module action."""

import asyncio
import secrets
import time
from typing import Annotated

from fastapi import Request
from pydantic import Field

from .errors import Failure
from .module_broker import handler
from .module_bundle import available as supplied_modules
from .module_bundle import read as read_supplied
from .module_capabilities import catalogue, require_target
from .module_fetch import fetch_package
from .modules import inspect_archive
from .modules.sandbox import require_runtime
from .schema import Model
from .workspace_schema import Digest, Identity


class InstallRequest(Model):
    preview_id: Identity
    digest: Digest
    accept_unverified: bool


class FetchRequest(Model):
    url: Annotated[str, Field(min_length=1, max_length=2048)]
    expected_digest: Digest | None = None
    allow_private_network: bool = False
    allow_http: bool = False


class Activation(Model):
    enabled: bool
    grants: Annotated[list[dict], Field(max_length=32)] = Field(default_factory=list)


class SuppliedRequest(Model):
    package_id: Annotated[str, Field(min_length=1, max_length=80)]


class Invocation(Model):
    workspace_id: Identity
    instance_id: Identity
    action: Annotated[str, Field(min_length=1, max_length=80)]
    targets: Annotated[list[Identity], Field(min_length=1, max_length=64)]
    parameters: dict = Field(default_factory=dict)


def install(app, service, principal):
    previews: dict[str, dict] = {}
    admission = asyncio.Lock()
    fetching = 0

    def actor(request, scope):
        value = principal(request, scope)
        if value.node_ids is not None or value.root_ids is not None:
            raise Failure("denied", "Module management requires unrestricted local access.", 403)
        return value.id

    async def inspect(data, owner, source):
        async with admission:
            now = time.monotonic()
            for key in list(previews):
                if previews[key]["expires"] < now:
                    previews.pop(key)
            if len(previews) >= 4:
                raise Failure("capacity", "Finish an existing package inspection before starting another.", 429)
            value = await asyncio.to_thread(inspect_archive, data)
            service.authorize(owner, "modules:manage")
            key = secrets.token_hex(16)
            previews[key] = {"inspection": value, "actor": owner, "expires": now + 300}
            return {**value.public(), "preview_id": key, "source": source, "expires_at": time.time() + 300}

    @app.get("/api/v1/modules")
    async def modules(request: Request):
        actor(request, "modules:read")
        return {"modules": service.modules.list()}

    @app.get("/api/v1/modules/sandbox")
    async def sandbox(request: Request):
        actor(request, "modules:manage")
        return (await service.module_runtime.sandbox.probe()).public()

    @app.get("/api/v1/module-targets")
    async def available_targets(request: Request):
        owner = actor(request, "modules:manage")
        return catalogue(service, owner)

    @app.get("/api/v1/supplied-modules")
    async def supplied(request: Request):
        actor(request, "modules:read")
        return {"modules": supplied_modules()}

    @app.post("/api/v1/supplied-module-previews")
    async def supplied_preview(body: SuppliedRequest, request: Request):
        owner = actor(request, "modules:manage")
        data = await asyncio.to_thread(read_supplied, body.package_id)
        return await inspect(data, owner, "Supplied with FICC")

    @app.post("/api/v1/module-install-previews")
    async def upload_preview(request: Request):
        owner = actor(request, "modules:manage")
        return await inspect(await request.body(), owner, "Local file")

    @app.post("/api/v1/module-fetch-previews")
    async def remote_preview(body: FetchRequest, request: Request):
        nonlocal fetching
        owner = actor(request, "modules:manage")
        if fetching >= 2:
            raise Failure("capacity", "Wait for a package download to finish.", 429)
        fetching += 1
        try:
            data = await fetch_package(body.url, body.expected_digest, body.allow_private_network, body.allow_http)
            return await inspect(data, owner, body.url)
        finally:
            fetching -= 1

    @app.post("/api/v1/modules", status_code=201)
    async def install_package(body: InstallRequest, request: Request):
        owner = actor(request, "modules:manage")
        async with admission:
            preview = previews.get(body.preview_id)
            if not preview or preview["actor"] != owner or preview["expires"] <= time.monotonic():
                raise Failure("preview_expired", "Inspect the package again before installation.", 409)
            if not body.accept_unverified:
                raise Failure("source_unverified", "Confirm that this package publisher is unverified.", 409)
            def publish():
                with service.store.lock:
                    service.authorize(owner, "modules:manage")
                    return service.modules.install(preview["inspection"], body.digest)
            value = await asyncio.to_thread(publish)
            previews.pop(body.preview_id)
        service.store.audit("module.install", body.digest, actor=owner)
        return value

    @app.delete("/api/v1/module-install-previews/{preview_id}")
    async def release_preview(preview_id: str, request: Request):
        owner = actor(request, "modules:manage")
        async with admission:
            preview = previews.get(preview_id)
            if preview and preview["actor"] == owner:
                previews.pop(preview_id)
        return {"removed": True}

    @app.post("/api/v1/modules/{digest}/activation")
    async def activate(digest: str, body: Activation, request: Request):
        owner = actor(request, "modules:manage")
        current = service.modules.get(digest)
        if body.enabled and current["manifest"].get("role") == "provider-adapter":
            raise Failure("adapter_grant_required", "Use Provider profiles to grant this adapter access to a registered account.", 409)
        sandbox_ready = False
        if current["manifest"]["runtime"]["kind"] != "declarative" and body.enabled:
            service.live()
            require_runtime(current["manifest"], service.modules.verify(digest))
            status = await service.module_runtime.sandbox.probe()
            if not status.available:
                raise Failure("module_sandbox_unavailable", status.reason, 503)
            sandbox_ready = True
        from .modules.registry import validate_grants
        optional = set(current["manifest"].get("optional_capabilities", []))
        grants = validate_grants(body.grants, current["manifest"]["capabilities"], optional) if body.enabled else []
        for grant in grants:
            for target in grant["target_ids"]:
                require_target(service, grant["capability"], target)
        service.authorize(owner, "modules:manage")
        value = service.modules.set_enabled(digest, body.enabled, body.grants, sandbox_ready=sandbox_ready)
        if not body.enabled:
            await service.module_runtime.stop(digest)
            await service.adapters.stop(digest)
        service.store.audit("module.enable" if body.enabled else "module.disable", digest, actor=owner)
        return value

    @app.delete("/api/v1/modules/{digest}")
    async def uninstall(digest: str, request: Request):
        owner = actor(request, "modules:manage")
        from .module_editor_store import retained
        if retained(service.store, digest=digest):
            raise Failure("editor_retained", "Resolve retained editor records before removing this package.", 409)
        from .module_activity import require_removable
        require_removable(service, digest=digest)
        from .module_adapter_store import retained as adapter_retained
        if adapter_retained(service.store, digest=digest):
            raise Failure("adapter_retained", "Remove adapter profiles and operation receipts before removing this package.", 409)
        service.modules.revoke(digest)
        await service.module_runtime.stop(digest)
        await service.adapters.stop(digest)
        service.modules.uninstall(digest)
        service.store.audit("module.uninstall", digest, actor=owner)
        return {"removed": True}

    @app.post("/api/v1/module-invocations")
    async def invoke(body: Invocation, request: Request):
        owner = actor(request, "modules:execute")
        service.live()
        service.authorize(owner, "workspaces:read")
        workspace = service.workspaces.get(body.workspace_id)
        instance = next((item for item in workspace["instances"] if item["id"] == body.instance_id), None)
        if instance is None:
            raise Failure("not_found", "The module instance was not found.", 404)
        allowed = instance.get("targets") or [body.workspace_id]
        if len(set(body.targets)) != len(body.targets) or set(body.targets) - set(allowed):
            raise Failure("module_target_denied", "The request exceeds this panel's selected targets.", 403)

        def check():
            service.authorize(owner, "modules:execute")
            service.authorize(owner, "workspaces:read")
            current = service.workspaces.get(body.workspace_id)
            if not any(item["id"] == body.instance_id and item["digest"] == instance["digest"]
                       and (item.get("targets") or [body.workspace_id]) == allowed
                       for item in current["instances"]):
                raise Failure("instance_changed", "The module instance changed.", 409)

        return await service.module_runtime.invoke(instance["digest"], body.action, body.targets,
                                                   body.parameters, check, broker=handler(service, owner, body.instance_id))
