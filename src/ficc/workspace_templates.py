# SPDX-License-Identifier: Apache-2.0
"""Share immutable panel recipes without copying data, targets, grants or private layouts."""

import secrets
import time
from typing import Annotated

from fastapi import Request
from pydantic import Field

from .errors import Failure
from .schema import Model
from .workspace_schema import Digest, Identity, Name, Revision, bounded

KEY = "workspace_templates"


class Panel(Model):
    digest: Digest
    title: Name


class Template(Model):
    id: Identity
    project_id: Identity
    subject_id: Identity
    name: Name
    version: Annotated[int, Field(ge=1, le=2**31 - 1)]
    created_at: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    panels: Annotated[list[Panel], Field(min_length=1, max_length=64)]


class Share(Model):
    workspace_id: Identity
    revision: Revision
    name: Name


def checked(values):
    if not isinstance(values, list) or len(values) > 128:
        raise ValueError("The workspace template catalogue is invalid or full.")
    result = [Template.model_validate(value).model_dump() for value in values]
    if len({value["id"] for value in result}) != len(result):
        raise ValueError("Workspace template identities must be unique.")
    bounded(result, 524288)
    return result


def validate_records(db):
    import json
    row = db.execute("SELECT value FROM settings WHERE key=:p0", (KEY,)).fetchone()
    if row:
        for value in checked(json.loads(row[0])):
            if not db.execute("SELECT 1 FROM projects WHERE id=:p0", (value["project_id"],)).fetchone():
                raise ValueError("The template project is unavailable.")


def install(app, service, principal):
    def actor(request, scope):
        value = principal(request, scope)
        if value.node_ids is not None or value.root_ids is not None:
            raise Failure("denied", "Template access requires unrestricted workspace access.", 403)
        return value

    def values():
        try:
            return checked(service.store.get_setting(KEY, []))
        except ValueError:
            raise Failure("template_invalid", "The saved template catalogue is unavailable.", 409) from None

    @app.get("/api/v1/workspace-templates")
    async def all_templates(request: Request):
        current = actor(request, "workspaces:read")
        return {"templates": [value for value in values() if value["project_id"] == current.project_id]}

    @app.post("/api/v1/workspace-templates", status_code=201)
    async def share(body: Share, request: Request):
        service.live()
        current = actor(request, "workspaces:write")
        current.require("workspaces:read")
        with service.store.lock, service.store.db:
            workspace = service.workspaces.scoped(current).get(body.workspace_id)
            service.workspaces.revision(workspace, body.revision)
            if not workspace["instances"]:
                raise Failure("template_empty", "Add at least one module before sharing a panel template.")
            saved = values()
            version = 1 + max((value["version"] for value in saved if value["project_id"] == current.project_id
                               and value["name"] == body.name), default=0)
            value = Template(id=secrets.token_hex(16), project_id=current.project_id, subject_id=current.subject_id,
                name=body.name, version=version, created_at=time.time(),
                panels=[Panel(digest=panel["digest"], title=panel["title"]) for panel in workspace["instances"]]).model_dump()
            try:
                checked([*saved, value])
            except ValueError:
                raise Failure("capacity", "Remove an unused template version before sharing another.", 409) from None
            service.store.set_setting(KEY, [*saved, value])
            service.store.audit("workspace.template.share", value["id"], actor=current.id)
            return value

    @app.delete("/api/v1/workspace-templates/{identity}")
    async def remove(identity: Identity, request: Request):
        service.live()
        current = actor(request, "workspaces:write")
        with service.store.lock, service.store.db:
            saved = values()
            value = next((item for item in saved if item["id"] == identity and item["project_id"] == current.project_id), None)
            if value is None:
                raise Failure("not_found", "The workspace template was not found.", 404)
            service.store.set_setting(KEY, [item for item in saved if item["id"] != identity])
            service.store.audit("workspace.template.remove", identity, actor=current.id)
        return {"removed": True}
