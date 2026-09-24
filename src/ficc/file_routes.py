# SPDX-License-Identifier: Apache-2.0
"""Expose authenticated root listings and confirmed file mutations."""

from fastapi import Request

from .errors import Failure
from .file_schema import Confirm, ContentPreview, FileOperation, Listing


def install(app, service, principal):
    files = service.files

    @app.get("/api/v1/file-roots")
    async def roots(request: Request):
        return await files.roots(principal(request).id)

    @app.post("/api/v1/files/list")
    async def listing(body: Listing, request: Request):
        return await files.listing(body.model_dump(), principal(request, "files:read").id)

    @app.post("/api/v1/files/preview")
    async def content_preview(body: ContentPreview, request: Request):
        return await files.content_preview(body.model_dump(), principal(request, "files:read").id)

    @app.post("/api/v1/file-operation-previews")
    async def preview(body: FileOperation, request: Request):
        return await files.preview(body.model_dump(), principal(request).id)

    @app.post("/api/v1/file-operations", status_code=202)
    async def submit(body: Confirm, request: Request):
        actor = principal(request).id
        value = await files.submit(body.preview_id, request.headers.get("idempotency-key", ""), actor)
        return files.view(value, actor)

    @app.get("/api/v1/file-operations")
    async def operations(request: Request):
        actor = principal(request, "files:read").id
        result = []
        for value in files.store.iterate():
            try:
                result.append(files.view(value, actor))
            except Failure as exc:
                if exc.status not in (403, 404):
                    raise
            if len(result) == 200:
                break
        return {"operations": result[:200]}

    @app.get("/api/v1/file-operations/{operation_id}")
    async def operation(operation_id: str, request: Request):
        return files.view(files.store.get(operation_id), principal(request, "files:read").id)

    @app.post("/api/v1/file-operations/{operation_id}/reconcile")
    async def reconcile(operation_id: str, request: Request):
        return await files.reconcile(operation_id, principal(request).id)
