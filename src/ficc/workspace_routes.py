# SPDX-License-Identifier: Apache-2.0
"""Expose revision-checked workspace and audio controls to authorised local clients."""

import re

from fastapi import Request

from .errors import Failure
from .module_activity import require_removable
from .module_capabilities import validate_instance
from .module_editor_store import retained as editor_retained
from .workspace_schema import (
    AudioLease,
    AudioLeaseOwner,
    AudioPreferences,
    InstanceState,
    SurfaceUpdate,
    ViewUpdate,
    WorkspaceCreate,
    WorkspaceUpdate,
)


def install(app, service, principal):
    spaces = service.workspaces

    def actor(request, scope):
        value = principal(request, scope)
        if value.node_ids is not None or value.root_ids is not None:
            raise Failure("denied", "This action requires unrestricted workspace access.", 403)
        return value.id

    def identity(value):
        if not re.fullmatch(r"[a-f0-9]{32}", value):
            raise Failure("invalid_identity", "The workspace or view identity is invalid.")
        return value

    @app.get("/api/v1/workspaces")
    async def all_workspaces(request: Request):
        actor(request, "workspaces:read")
        return {"workspaces": spaces.all()}

    @app.get("/api/v1/workspace-layouts")
    async def layouts(request: Request):
        actor(request, "workspaces:read")
        return spaces.layouts()

    @app.delete("/api/v1/workspace-surfaces/{surface_id}")
    async def delete_surface(surface_id: str, revision: int, request: Request):
        owner = actor(request, "workspaces:write")
        spaces.delete_surface(identity(surface_id), revision)
        service.store.audit("workspace.surface.remove", surface_id, actor=owner)
        return {"removed": True}

    @app.delete("/api/v1/workspaces/{workspace_id}/views/{view_id}")
    async def delete_view(workspace_id: str, view_id: str, revision: int, request: Request):
        owner = actor(request, "workspaces:write")
        spaces.delete_view(identity(workspace_id), identity(view_id), revision)
        service.store.audit("workspace.view.remove", view_id, actor=owner)
        return {"removed": True}

    @app.post("/api/v1/workspaces", status_code=201)
    async def create(body: WorkspaceCreate, request: Request):
        owner = actor(request, "workspaces:write")
        value = spaces.create(body.name)
        service.store.audit("workspace.create", value["id"], actor=owner)
        return value

    @app.get("/api/v1/workspaces/{workspace_id}")
    async def get(workspace_id: str, request: Request):
        actor(request, "workspaces:read")
        return spaces.get(identity(workspace_id))

    @app.put("/api/v1/workspaces/{workspace_id}")
    async def update(workspace_id: str, body: WorkspaceUpdate, request: Request):
        owner = actor(request, "workspaces:write")
        current = spaces.get(identity(workspace_id))
        existing = {item["id"]: (item["digest"], item.get("targets", [])) for item in current["instances"]}
        proposed = {item.id: (item.digest, item.targets) for item in body.instances}
        for instance_id, configuration in existing.items():
            if (proposed.get(instance_id) != configuration
                    and editor_retained(service.store, workspace_id=workspace_id, instance_id=instance_id)):
                raise Failure("editor_retained", "Recover and remove retained edit copies before changing this panel.", 409)
            if proposed.get(instance_id) != configuration:
                require_removable(service, instance_id=instance_id)
        for item in body.instances:
            if existing.get(item.id) != (item.digest, item.targets):
                validate_instance(service, workspace_id, item)
        value = spaces.update(workspace_id, body)
        service.store.audit("workspace.update", workspace_id, actor=owner)
        return value

    @app.put("/api/v1/workspaces/{workspace_id}/instances/{instance_id}/state")
    async def save_state(workspace_id: str, instance_id: str, body: InstanceState, request: Request):
        actor(request, "workspaces:write")
        value = spaces.get(identity(workspace_id))
        identity(instance_id)
        item = next((item for item in value["instances"] if item["id"] == instance_id), None)
        if item is None:
            raise Failure("not_found", "The module instance was not found.", 404)
        service.modules.require(item["digest"], "workspace:write", [workspace_id])
        item["state"] = body.state
        return spaces.update(workspace_id, WorkspaceUpdate(
            revision=body.revision, name=value["name"], instances=value["instances"]))

    @app.delete("/api/v1/workspaces/{workspace_id}")
    async def delete(workspace_id: str, revision: int, request: Request):
        owner = actor(request, "workspaces:write")
        if editor_retained(service.store, workspace_id=identity(workspace_id)):
            raise Failure("editor_retained", "Recover and remove retained edit copies before deleting this workspace.", 409)
        for item in spaces.get(workspace_id)["instances"]:
            require_removable(service, instance_id=item["id"])
        spaces.delete(identity(workspace_id), revision)
        service.store.audit("workspace.delete", workspace_id, actor=owner)
        return {"deleted": True}

    @app.get("/api/v1/workspaces/{workspace_id}/views/{view_id}")
    async def view(workspace_id: str, view_id: str, request: Request):
        actor(request, "workspaces:read")
        return spaces.view(identity(workspace_id), identity(view_id))

    @app.put("/api/v1/workspaces/{workspace_id}/views/{view_id}")
    async def save_view(workspace_id: str, view_id: str, body: ViewUpdate, request: Request):
        actor(request, "workspaces:write")
        return spaces.save_view(identity(workspace_id), identity(view_id), body)

    @app.get("/api/v1/audio/preferences")
    async def preferences(request: Request):
        actor(request, "audio:playback")
        return service.audio.preferences()

    @app.get("/api/v1/workspace-surfaces/{surface_id}")
    async def surface(surface_id: str, request: Request):
        actor(request, "workspaces:read")
        return spaces.surface(identity(surface_id))

    @app.put("/api/v1/workspace-surfaces/{surface_id}")
    async def save_surface(surface_id: str, body: SurfaceUpdate, request: Request):
        actor(request, "workspaces:write")
        return spaces.save_surface(identity(surface_id), body)

    @app.put("/api/v1/audio/preferences")
    async def save_preferences(body: AudioPreferences, request: Request):
        actor(request, "audio:playback")
        return service.audio.save_preferences(body)

    @app.post("/api/v1/audio/leases")
    async def acquire(body: AudioLease, request: Request):
        owner = actor(request, "audio:playback")
        return service.audio.acquire(owner, body.instance_id, body.surface_id)

    @app.put("/api/v1/audio/leases/{lease_id}")
    async def heartbeat(lease_id: str, body: AudioLeaseOwner, request: Request):
        owner = actor(request, "audio:playback")
        return service.audio.heartbeat(identity(lease_id), owner, body.surface_id)

    @app.delete("/api/v1/audio/leases/{lease_id}")
    async def release(lease_id: str, body: AudioLeaseOwner, request: Request):
        owner = actor(request, "audio:playback")
        service.audio.release(identity(lease_id), owner, body.surface_id)
        return {"released": True}
