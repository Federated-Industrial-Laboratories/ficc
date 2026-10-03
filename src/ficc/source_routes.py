# SPDX-License-Identifier: Apache-2.0
"""Expose the provider catalogue and project data pipeline workflow."""

from fastapi import Query, Request

from .file_numbers import wire
from .identity_store import LOCAL_OWNER
from .source_schema import (
    Connection,
    CreateUpload,
    Describe,
    Enabled,
    RegisteredQuery,
    Run,
    SourceLimits,
    UploadOperation,
    Values,
)


def install(app, service, principal):
    sources = service.sources

    @app.get("/api/v1/data-providers")
    async def providers(request: Request):
        return sources.providers(principal(request).id)

    @app.get("/api/v1/source-limits")
    async def limits(request: Request):
        principal(request, "data:read")
        return wire(sources.limits())

    @app.put("/api/v1/source-limits")
    async def set_limits(body: SourceLimits, request: Request):
        from .errors import Failure
        current = principal(request, "data:manage")
        if current.subject_id != LOCAL_OWNER or current.node_ids is not None or current.root_ids is not None:
            raise Failure("denied", "An unrestricted local owner is required to configure source limits.", 403)
        if sources.tasks:
            raise Failure("source_busy", "Wait for active data operations before changing limits.", 409)
        import asyncio
        service.live()
        service.store.set_setting("source_limits", body.model_dump())
        sources.workers = asyncio.Semaphore(body.workers)
        return wire(sources.limits())

    @app.get("/api/v1/sources")
    async def listing(request: Request, before: str | None = Query(default=None, pattern=r"^[a-f0-9]{32}$")):
        return wire(sources.all("source_connections", principal(request).id, before))

    @app.post("/api/v1/sources", status_code=201)
    async def create(body: Connection, request: Request):
        return wire(await sources.create(body.model_dump(), request.headers.get("idempotency-key", ""), principal(request).id))

    @app.get("/api/v1/sources/{identity}")
    async def source(identity: str, request: Request):
        return wire(sources.view("source_connections", sources.connection(identity, principal(request).id)))

    @app.put("/api/v1/sources/{identity}/approval")
    async def approval(identity: str, body: Enabled, request: Request):
        return sources.enabled(identity, body.model_dump(), principal(request).id)

    @app.get("/api/v1/sources/{identity}/catalogue")
    async def catalogue(identity: str, request: Request, cursor: str | None = Query(default=None, max_length=2048)):
        return wire(await sources.inspect(identity, principal(request).id, "catalogue", {"cursor": cursor}))

    @app.post("/api/v1/sources/{identity}/describe")
    async def describe(identity: str, body: Describe, request: Request):
        return wire(await sources.inspect(identity, principal(request).id, "describe", body.model_dump()))

    @app.get("/api/v1/source-queries")
    async def queries(request: Request, before: str | None = Query(default=None, pattern=r"^[a-f0-9]{32}$")):
        return sources.all("source_queries", principal(request).id, before)

    @app.post("/api/v1/sources/{identity}/queries", status_code=201)
    async def register(identity: str, body: RegisteredQuery, request: Request):
        return sources.register(identity, body.model_dump(), request.headers.get("idempotency-key", ""), principal(request).id)

    @app.post("/api/v1/source-queries/{identity}/preview")
    async def preview(identity: str, body: Values, request: Request):
        return wire(await sources.preview(identity, body.parameters, principal(request).id))

    @app.post("/api/v1/source-queries/{identity}/runs", status_code=202)
    async def submit(identity: str, body: Run, request: Request):
        return wire(await sources.submit(identity, body.model_dump(), request.headers.get("idempotency-key", ""), principal(request).id))

    @app.get("/api/v1/source-runs")
    async def runs(request: Request, before: str | None = Query(default=None, pattern=r"^[a-f0-9]{32}$")):
        return wire(sources.all("source_runs", principal(request).id, before))

    @app.get("/api/v1/source-runs/{identity}")
    async def status(identity: str, request: Request):
        return wire(sources.status(identity, principal(request).id))

    @app.post("/api/v1/source-runs/{identity}/cancel")
    async def cancel(identity: str, request: Request):
        return wire(await sources.cancel(identity, principal(request).id))

    @app.get("/api/v1/source-uploads")
    async def uploads(request: Request, before: str | None = Query(default=None, pattern=r"^[a-f0-9]{32}$")):
        return wire(sources.all("source_uploads", principal(request).id, before))

    @app.post("/api/v1/sources/{identity}/uploads", status_code=202)
    async def begin_upload(identity: str, body: CreateUpload, request: Request):
        return wire(await sources.uploads.begin(identity, body.model_dump(), request.headers.get("idempotency-key", ""), principal(request).id))

    @app.get("/api/v1/source-uploads/{identity}")
    async def upload(identity: str, request: Request):
        return wire(sources.uploads.get(identity, principal(request).id))

    @app.post("/api/v1/source-uploads/{identity}/operations", status_code=202)
    async def upload_operation(identity: str, body: UploadOperation, request: Request):
        return wire(await sources.uploads.operate(identity, body.model_dump(), request.headers.get("idempotency-key", ""), principal(request).id))
