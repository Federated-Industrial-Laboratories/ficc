# SPDX-License-Identifier: Apache-2.0
"""Expose local identity administration and the selected project of each session."""

from typing import Annotated

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import Field

from .errors import Failure
from .identity_store import PROJECT_SCOPES
from .remote_routes import session_cookie
from .schema import Model
from .workspace_schema import Identity, Name, Revision


class Create(Model):
    label: Name


class Update(Create):
    disabled: bool
    revision: Revision


class Membership(Model):
    scopes: Annotated[list[str], Field(max_length=64)]
    revision: Revision


class ProjectSelection(Model):
    project_id: Identity


class ResourceSelection(Model):
    node_ids: Annotated[list[str], Field(max_length=128)]
    root_ids: Annotated[list[str], Field(max_length=64)]
    revision: Revision


def install(app, service, principal, session, cookie):
    identities = service.auth.identities

    def owner(request):
        value = principal(request, "identities:manage")
        if not value.local_owner or value.node_ids is not None or value.root_ids is not None:
            raise Failure("denied", "Local owner identity administration is required.", 403)
        return value

    @app.get("/api/v1/projects")
    async def projects(request: Request):
        value = principal(request)
        return {"projects": identities.projects(value.subject_id), "project_scopes": sorted(PROJECT_SCOPES)}

    @app.post("/api/v1/session/project")
    async def select(body: ProjectSelection, request: Request):
        current = principal(request)
        secret, value = service.auth.switch_project(current.id, body.project_id)
        response = JSONResponse(session(value))
        session_cookie(response, cookie, secret, value.expires_at, service.settings.remote is not None)
        service.store.audit("session.project", body.project_id, actor=value.id)
        return response

    @app.get("/api/v1/identities")
    async def users(request: Request):
        owner(request)
        return {"identities": identities.users()}

    @app.post("/api/v1/identities", status_code=201)
    async def create_user(body: Create, request: Request):
        actor = owner(request)
        result = identities.create("user", body.label)
        service.store.audit("identity.create", result["id"], actor=actor.id, subject_id=actor.subject_id, project_id=actor.project_id)
        return result

    @app.post("/api/v1/projects", status_code=201)
    async def create_project(body: Create, request: Request):
        actor = owner(request)
        result = identities.create("project", body.label)
        service.store.audit("project.create", result["id"], actor=actor.id, subject_id=actor.subject_id, project_id=actor.project_id)
        return result

    @app.put("/api/v1/identities/{identity}")
    async def update_user(identity: Identity, body: Update, request: Request):
        actor = owner(request)
        result = identities.update("user", identity, body.label, body.disabled, body.revision)
        service.store.audit("identity.update", identity, actor=actor.id, subject_id=actor.subject_id, project_id=actor.project_id)
        return result

    @app.put("/api/v1/projects/{identity}")
    async def update_project(identity: Identity, body: Update, request: Request):
        actor = owner(request)
        result = identities.update("project", identity, body.label, body.disabled, body.revision)
        service.store.audit("project.update", identity, actor=actor.id, subject_id=actor.subject_id, project_id=actor.project_id)
        return result

    @app.get("/api/v1/projects/{project}/members")
    async def members(project: Identity, request: Request):
        owner(request)
        return {"members": identities.members(project)}

    @app.get("/api/v1/project-resource-options")
    async def resource_options(request: Request):
        owner(request)
        from .module_windows_store import Records
        nodes = [{"id": item["id"], "name": item["name"], "kind": "Linux SSH"} for item in service.store.nodes()]
        nodes.extend({"id": item["id"], "name": item["name"], "kind": "Windows"} for item in Records(service.store).all())
        return {"nodes": nodes, "roots": [{key: item[key] for key in ("id", "label", "node_id", "read_only")}
                                         for item in service.files.registered()]}

    @app.get("/api/v1/projects/{project}/resources")
    async def project_resources(project: Identity, request: Request):
        owner(request)
        identities.project(project)
        return service.auth.resources.get(project)

    @app.put("/api/v1/projects/{project}/resources")
    async def set_resources(project: Identity, body: ResourceSelection, request: Request):
        actor = owner(request)
        value = service.auth.resources.save(project, body.node_ids, body.root_ids, body.revision)
        service.store.audit("project.resources", project, actor=actor.id, subject_id=actor.subject_id, project_id=actor.project_id)
        return value

    @app.put("/api/v1/projects/{project}/members/{subject}")
    async def set_member(project: Identity, subject: Identity, body: Membership, request: Request):
        actor = owner(request)
        result = identities.membership(project, subject, body.scopes, body.revision)
        service.store.audit("project.membership", project + "/" + subject, actor=actor.id, subject_id=actor.subject_id, project_id=actor.project_id)
        return result
