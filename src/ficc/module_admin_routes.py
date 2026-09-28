# SPDX-License-Identifier: Apache-2.0
"""Expose confirmed administration with action-specific authority and retained history."""

from typing import Annotated, Literal

from fastapi import Request
from ficc_node.admin_spec import capability
from pydantic import Field

from .errors import Failure
from .module_activity import history
from .module_containers_routes import Removal, Resolution
from .module_vm_routes import Commit, Context, Operation, Preview, instance_guard
from .schema import Model
from .workspace_schema import Identity


class Profile(Model):
    node_id: Annotated[str, Field(min_length=1, max_length=128)]
    manager: Literal["user", "system"] = "user"
    profile_id: Identity | None = None
    enabled: bool = True


def install(app, service, principal):
    host = service.administration

    def actor(request):
        value = principal(request, "admin:read")
        if value.root_ids is not None:
            raise Failure("denied", "A folder-restricted credential cannot administer systems.", 403)
        return value.id

    def selected_preview(owner, body):
        value = host.previews.get(body.preview_id)
        if value is None or value["actor"] != owner:
            raise Failure("admin_preview_expired", "Create a new administration preview.", 409)
        return value

    def mutation(owner, body, value):
        service.authorize(owner, capability(value["action"]))
        return instance_guard(service, owner, body, value)

    @app.get("/api/v1/admin-profiles")
    async def profiles(request: Request):
        return {"profiles": host.profiles(actor(request))}

    @app.put("/api/v1/admin-profiles")
    async def profile(body: Profile, request: Request):
        owner = actor(request)
        principal(request, "nodes:write", body.node_id)
        return await host.set_profile(owner, **body.model_dump())

    @app.delete("/api/v1/admin-profiles/{profile_id}")
    async def remove_profile(profile_id: Identity, request: Request):
        owner = actor(request)
        principal(request, "nodes:write", host.records.profile(profile_id)["node_id"])
        return await host.remove_profile(owner, profile_id)

    @app.post("/api/v1/module-admin/preview")
    async def preview(body: Preview, request: Request):
        owner = actor(request)
        value = selected_preview(owner, body)
        return host.preview_for_confirmation(owner, body.preview_id, mutation(owner, body, value))

    @app.post("/api/v1/module-admin/commit")
    async def commit(body: Commit, request: Request):
        owner = actor(request)
        key = request.headers.get("idempotency-key")
        value = host.records.existing(owner, key) if key else None
        value = value or selected_preview(owner, body)
        return await host.commit(owner, body.preview_id, key, mutation(owner, body, value))

    @app.post("/api/v1/module-admin/history")
    async def all_operations(body: Context, request: Request):
        return history(service, host, actor(request), body, "admin:read", instance_guard)

    @app.post("/api/v1/module-admin/operation")
    async def operation(body: Operation, request: Request):
        owner = actor(request)
        value = host.records.get(body.operation_id)
        return await host.operation(owner, body.operation_id, instance_guard(service, owner, body, value))

    @app.post("/api/v1/module-admin/resolve")
    async def resolve(body: Resolution, request: Request):
        owner = actor(request)
        value = host.records.get(body.operation_id)
        return await host.resolve(owner, body.operation_id, body.resource_ids, mutation(owner, body, value))

    @app.post("/api/v1/module-admin/forget")
    async def forget(body: Removal, request: Request):
        owner = actor(request)
        value = host.records.get(body.operation_id)
        return await host.forget(owner, body.operation_id, mutation(owner, body, value))
