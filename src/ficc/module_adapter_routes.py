# SPDX-License-Identifier: Apache-2.0
"""Require explicit account authority for each immutable provider adapter binding."""

from typing import Annotated, Literal

from fastapi import Request
from pydantic import Field

from .errors import Failure
from .schema import Model
from .workspace_schema import Digest, Identity


class Profile(Model):
    digest: Digest
    endpoint_kind: Literal["linux-ssh", "windows"]
    endpoint_id: Identity
    transport_binding_id: Identity


class Grant(Model):
    expected_revision: Annotated[int, Field(ge=1, le=2**53 - 2)]
    confirm: Literal[True]


class Removal(Model):
    confirm: Literal[True]


class Binding(Model):
    endpoint_kind: Literal["linux-ssh"]
    endpoint_id: Identity
    socket_path: Annotated[str, Field(min_length=1, max_length=4096)]


def install(app, service, principal):
    def actor(request, scope, endpoint_id=None):
        value = principal(request, scope, endpoint_id)
        if value.root_ids is not None:
            raise Failure("denied", "A folder-restricted credential cannot manage provider profiles.", 403)
        return value.id

    @app.get("/api/v1/adapter-bindings")
    async def bindings(endpoint_kind: Literal["linux-ssh", "windows"], endpoint_id: Identity, request: Request):
        owner = actor(request, "providers:write", endpoint_id)
        return {"bindings": await service.adapters.bindings(owner, endpoint_kind, endpoint_id,
            check=lambda: service.authorize(owner, "providers:write", endpoint_id))}

    @app.post("/api/v1/adapter-bindings", status_code=201)
    async def register_binding(body: Binding, request: Request):
        owner = actor(request, "providers:write", body.endpoint_id)
        return await service.adapters.register_binding(owner, body.endpoint_kind, body.endpoint_id,
            {"socket_path": body.socket_path}, check=lambda: service.authorize(owner, "providers:write", body.endpoint_id))

    @app.get("/api/v1/adapter-profiles")
    async def profiles(request: Request):
        return {"profiles": service.adapters.profiles(actor(request, "vm:read"))}

    @app.post("/api/v1/adapter-profiles", status_code=201)
    async def create(body: Profile, request: Request):
        owner = actor(request, "providers:write", body.endpoint_id)
        return await service.adapters.create(owner, body.digest, body.endpoint_kind, body.endpoint_id,
            body.transport_binding_id, check=lambda: service.authorize(owner, "providers:write", body.endpoint_id))

    @app.post("/api/v1/adapter-profiles/{profile_id}/grant")
    async def grant(profile_id: Identity, body: Grant, request: Request):
        owner = actor(request, "providers:write")
        return await service.adapters.grant(owner, profile_id, body.expected_revision, confirmed=body.confirm,
            check=lambda: service.authorize(owner, "providers:write"))

    @app.post("/api/v1/adapter-profiles/{profile_id}/revoke")
    async def revoke(profile_id: Identity, request: Request):
        return await service.adapters.revoke(actor(request, "providers:write"), profile_id)

    @app.delete("/api/v1/adapter-profiles/{profile_id}")
    async def remove(profile_id: Identity, body: Removal, request: Request):
        return await service.adapters.remove(actor(request, "providers:write"), profile_id)
