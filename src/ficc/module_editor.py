# SPDX-License-Identifier: Apache-2.0
"""Expose authenticated host editor operations through explicit module instances."""

from fastapi import Request

from .module_editor_schema import Cleanup, Context, Copy, Listing, Read, Receipt, Save
from .module_editor_service import Editor


def install(app, service, principal):
    editor = Editor(service)
    service.module_editor = editor

    @app.post("/api/v1/module-editor/roots")
    async def roots(body: Context, request: Request):
        return await editor.roots(principal(request, "workspaces:read").id, body.workspace_id, body.instance_id)

    @app.post("/api/v1/module-editor/list")
    async def listing(body: Listing, request: Request):
        return await editor.listing(principal(request, "files:read").id, body.model_dump())

    @app.post("/api/v1/module-editor/read")
    async def read(body: Read, request: Request):
        return await editor.read(principal(request, "files:read").id, body.model_dump())

    @app.post("/api/v1/module-editor/save")
    async def save(body: Save, request: Request):
        return await editor.save(principal(request, "files:write").id, body.model_dump(), request.headers.get("idempotency-key"))

    @app.post("/api/v1/module-editor/operations")
    async def operations(body: Context, request: Request):
        return await editor.operations(principal(request, "files:read").id, body.model_dump())

    @app.post("/api/v1/module-editor/status")
    async def status(body: Receipt, request: Request):
        return await editor.status(principal(request, "files:read").id, body.model_dump())

    @app.post("/api/v1/module-editor/recovery")
    async def recovery(body: Copy, request: Request):
        return await editor.recovery(principal(request, "files:read").id, body.model_dump(by_alias=True))

    @app.post("/api/v1/module-editor/cleanup")
    async def cleanup(body: Cleanup, request: Request):
        return await editor.cleanup(principal(request, "files:write").id, body.model_dump())

    @app.post("/api/v1/module-editor/remove-receipt")
    async def remove(body: Receipt, request: Request):
        return await editor.remove(principal(request, "files:write").id, body.model_dump())
