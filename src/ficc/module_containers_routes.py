# SPDX-License-Identifier: Apache-2.0
"""Expose container profiles, confirmed actions and recoverable receipt history."""

from typing import Annotated, Literal

from fastapi import Request
from pydantic import Field

from .errors import Failure
from .module_activity import history
from .module_vm_routes import Commit, Context, Operation, Preview, instance_guard
from .schema import Model
from .workspace_schema import Identity


class Profile(Model):
    node_id: Annotated[str, Field(min_length=1, max_length=128)]
    provider: Literal["docker", "podman", "kubernetes"]
    connection: Literal["rootful", "rootless", "context"]
    context: Annotated[str, Field(max_length=128)] = ""
    namespace: Annotated[str, Field(max_length=63)] = ""
    profile_id: Identity | None = None
    enabled: bool = True


class Resolution(Operation):
    resource_ids: Annotated[list[Annotated[str, Field(min_length=1, max_length=160)]], Field(min_length=1, max_length=64)]
    confirm: Literal[True]


class Removal(Operation):
    confirm: Literal[True]


def install(app, service, principal):
    host = service.containers

    def actor(request, scope):
        value = principal(request, scope)
        if value.root_ids is not None:
            raise Failure("denied", "A folder-restricted credential cannot manage containers.", 403)
        return value.id

    def preview_guard(owner, body):
        value = host.previews.get(body.preview_id)
        if value is None or value["actor"] != owner:
            raise Failure("container_preview_expired", "Create a new container preview.", 409)
        return instance_guard(service, owner, body, value)

    @app.get("/api/v1/container-profiles")
    async def profiles(request: Request):
        return {"profiles": host.profiles(actor(request, "container:read"))}

    @app.put("/api/v1/container-profiles")
    async def profile(body: Profile, request: Request):
        owner = actor(request, "nodes:write")
        try:
            return await host.set_profile(owner, **body.model_dump())
        except ValueError as exc:
            raise Failure("container_profile", "The provider connection, context or namespace is invalid.") from exc

    @app.delete("/api/v1/container-profiles/{profile_id}")
    async def remove_profile(profile_id: Identity, request: Request):
        return await host.remove_profile(actor(request, "nodes:write"), profile_id)

    @app.post("/api/v1/module-containers/preview")
    async def preview(body: Preview, request: Request):
        owner = actor(request, "container:power")
        return host.preview_for_confirmation(owner, body.preview_id, preview_guard(owner, body))

    @app.post("/api/v1/module-containers/commit")
    async def commit(body: Commit, request: Request):
        owner = actor(request, "container:power")
        key = request.headers.get("idempotency-key")
        previous = host.records.existing(owner, key) if key else None
        check = instance_guard(service, owner, body, previous) if previous else preview_guard(owner, body)
        return await host.commit(owner, body.preview_id, key, check)

    @app.post("/api/v1/module-containers/history")
    async def all_operations(body: Context, request: Request):
        return history(service, host, actor(request, "container:read"), body, "container:read", instance_guard)

    @app.post("/api/v1/module-containers/operation")
    async def operation(body: Operation, request: Request):
        owner = actor(request, "container:read")
        value = host.records.get(body.operation_id)
        return await host.operation(owner, body.operation_id, instance_guard(service, owner, body, value))

    @app.post("/api/v1/module-containers/resolve")
    async def resolve(body: Resolution, request: Request):
        owner = actor(request, "container:power")
        value = host.records.get(body.operation_id)
        return await host.resolve(owner, body.operation_id, body.resource_ids, instance_guard(service, owner, body, value))

    @app.post("/api/v1/module-containers/forget")
    async def forget(body: Removal, request: Request):
        owner = actor(request, "container:power")
        value = host.records.get(body.operation_id)
        return await host.forget(owner, body.operation_id, instance_guard(service, owner, body, value))
