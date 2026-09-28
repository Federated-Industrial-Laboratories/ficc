# SPDX-License-Identifier: Apache-2.0
"""Register revision-bound Windows endpoints through the local host controls."""

import ssl
from typing import Annotated, Literal

from fastapi import Request
from pydantic import Field

from .errors import Failure
from .schema import Model
from .workspace_schema import Digest, Identity

Port = Annotated[int, Field(ge=1, le=65535)]
Revision = Annotated[int, Field(ge=1, le=2**53 - 2)]
Name = Annotated[str, Field(min_length=1, max_length=128)]


class Credentials(Model):
    username: Name
    password: Annotated[str, Field(min_length=1, max_length=256)]
    domain: Annotated[str, Field(max_length=253)] = ""


class Command(Model):
    name: Annotated[str, Field(min_length=1, max_length=96)]
    parameters: Annotated[list[Annotated[str, Field(min_length=1, max_length=64)]], Field(max_length=16)]


class Display(Model):
    port: Port = 2179
    certificate_sha256: Digest
    credentials: Credentials | None = None


class Endpoint(Model):
    name: Name
    host: Annotated[str, Field(min_length=1, max_length=253)]
    port: Port = 5986
    configuration: Annotated[str, Field(min_length=1, max_length=64)]
    commands: Annotated[list[Command], Field(min_length=1, max_length=16)]
    certificate_sha256: Digest
    ca_pem: Annotated[str, Field(min_length=1, max_length=65536)] | None = None
    credentials: Credentials | None = None
    vmconnect: Display | None = None
    enabled: bool = False


class Update(Endpoint):
    expected_revision: Revision


class Activation(Model):
    expected_revision: Revision
    enabled: bool


class Removal(Model):
    expected_revision: Revision
    confirm: Literal[True]


def install(app, service, principal):
    async def save(owner, identity, value, revision):
        try:
            return await service.windows.set_endpoint(owner, identity, value, revision)
        except (ValueError, ssl.SSLError) as exc:
            raise Failure("windows_endpoint_invalid", "The Windows endpoint fields, credentials or trust data are invalid.", 422) from exc

    def payload(body):
        value = body.model_dump(exclude={"expected_revision"})
        for key in ("ca_pem", "credentials"):
            if value[key] is None:
                value.pop(key)
        if value["vmconnect"] is not None and value["vmconnect"]["credentials"] is None:
            value["vmconnect"].pop("credentials")
        return value

    def actor(request, scope, endpoint_id=None):
        value = principal(request, scope, endpoint_id)
        if value.root_ids is not None or (scope == "nodes:write" and value.node_ids is not None):
            raise Failure("denied", "Windows endpoint changes require unrestricted local access.", 403)
        return value.id

    @app.get("/api/v1/windows-endpoints")
    async def endpoints(request: Request):
        return {"endpoints": service.windows.endpoints(actor(request, "nodes:read"))}

    @app.post("/api/v1/windows-endpoints", status_code=201)
    async def create(body: Endpoint, request: Request):
        owner = actor(request, "nodes:write")
        return await save(owner, None, payload(body), None)

    @app.put("/api/v1/windows-endpoints/{endpoint_id}")
    async def update(endpoint_id: Identity, body: Update, request: Request):
        owner = actor(request, "nodes:write", endpoint_id)
        return await save(owner, endpoint_id, payload(body), body.expected_revision)

    @app.post("/api/v1/windows-endpoints/{endpoint_id}/activation")
    async def activate(endpoint_id: Identity, body: Activation, request: Request):
        owner = actor(request, "nodes:write", endpoint_id)
        return await service.windows.set_enabled(owner, endpoint_id, body.enabled, body.expected_revision)

    @app.delete("/api/v1/windows-endpoints/{endpoint_id}")
    async def remove(endpoint_id: Identity, body: Removal, request: Request):
        owner = actor(request, "nodes:write", endpoint_id)
        return await service.windows.remove_endpoint(owner, endpoint_id, body.expected_revision)
