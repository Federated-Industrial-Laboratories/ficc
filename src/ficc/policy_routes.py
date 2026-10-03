# SPDX-License-Identifier: Apache-2.0
"""Expose explicit security-package administration and effective access previews."""

import asyncio
import base64
from typing import Annotated, Any

from fastapi import APIRouter, Request
from fastapi.responses import Response
from fastapi.routing import APIRoute
from pydantic import Field

from .errors import Failure
from .policy_packages import MAX_ARCHIVE
from .schema import Model
from .workspace_schema import Identity, Revision


class Publisher(Model):
    id: Annotated[str, Field(min_length=1, max_length=64)]
    public_key: Annotated[str, Field(min_length=1, max_length=1024)]
    enabled: bool
    revision: Revision


class Package(Model):
    archive_base64: Annotated[str, Field(min_length=1, max_length=(MAX_ARCHIVE + 2) // 3 * 4)]


class Activation(Model):
    digest: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    revision: Revision


class Binding(Model):
    roles: Annotated[list[str], Field(max_length=64)]
    revision: Revision


class Preview(Model):
    requests: Annotated[list[dict[str, Any]], Field(min_length=1, max_length=64)]
    digest: Annotated[str | None, Field(pattern=r"^[a-f0-9]{64}$")] = None
    subject_id: Identity | None = None
    project_id: Identity | None = None


class PolicyRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def respond(request):
            try:
                return await handler(request)
            except ValueError as exc:
                raise Failure("invalid_policy", str(exc)) from None
            except OSError:
                raise Failure("policy_unavailable", "The policy service is unavailable. Access is denied.", 503) from None
        return respond


def install(app, service, principal):
    host = service.policies
    router = APIRouter(route_class=PolicyRoute)

    def owner(request):
        value = principal(request)
        return host.owner(value.id)

    @router.get("/api/v1/policy-status")
    async def status(request: Request):
        principal(request)
        value = host.status()
        return {key: value[key] for key in ("revision", "required", "ready", "error", "contributor_enforcement")}

    @router.get("/api/v1/policies")
    async def policies(request: Request):
        owner(request)
        return {"state": host.status(), "publishers": host.records.publishers(), "packages": host.records.packages()}

    @router.put("/api/v1/policy-publishers")
    async def publisher(body: Publisher, request: Request):
        actor = owner(request)
        return host.trust(body.id, body.public_key, body.enabled, body.revision, actor.id)

    @router.post("/api/v1/policy-packages", status_code=201)
    async def package(body: Package, request: Request):
        actor = owner(request)
        try:
            raw = base64.b64decode(body.archive_base64, validate=True)
        except ValueError:
            raise ValueError("The policy archive encoding is invalid.") from None
        return await asyncio.to_thread(host.install, raw, actor.id)

    @router.get("/api/v1/policy-packages/{digest}")
    async def download(digest: str, request: Request):
        owner(request)
        with service.store.lock:
            host.records.package(digest)
            raw = bytes(service.store.db.execute("SELECT archive FROM policy_packages WHERE digest=:p0", (digest,)).fetchone()[0])
        return Response(raw, media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="policy.zip"'})

    @router.post("/api/v1/policy-activation")
    async def activate(body: Activation, request: Request):
        actor = owner(request)
        return await asyncio.to_thread(host.activate, body.digest, body.revision, actor.id)

    @router.get("/api/v1/projects/{project}/policy-roles")
    async def roles(project: Identity, request: Request):
        owner(request)
        return {"bindings": host.records.bindings(project)}

    @router.put("/api/v1/projects/{project}/policy-roles/{subject}")
    async def bind(project: Identity, subject: Identity, body: Binding, request: Request):
        actor = owner(request)
        return host.bind(project, subject, body.roles, body.revision, actor.id)

    @router.post("/api/v1/policy-preview")
    async def preview(body: Preview, request: Request):
        actor = principal(request)
        return await asyncio.to_thread(host.preview, actor.id, body.requests, digest=body.digest,
                                       subject=body.subject_id, project=body.project_id)

    app.include_router(router)
