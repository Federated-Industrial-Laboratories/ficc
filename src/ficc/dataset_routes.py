# SPDX-License-Identifier: Apache-2.0
"""Expose project-isolated dataset registration, manifests and source verification."""

from fastapi import Query, Request

from .dataset_schema import CreateDataset
from .file_numbers import wire


def install(app, service, principal):
    datasets = service.datasets

    @app.get("/api/v1/datasets")
    async def listing(request: Request, before: str | None = Query(default=None, pattern=r"^[a-f0-9]{32}$")):
        return wire(datasets.all(principal(request).id, before))

    @app.post("/api/v1/datasets", status_code=201)
    async def create(body: CreateDataset, request: Request):
        return wire(await datasets.create(body.model_dump(by_alias=True), request.headers.get("idempotency-key", ""), principal(request).id))

    @app.get("/api/v1/datasets/{identity}")
    async def detail(identity: str, request: Request):
        return wire(datasets.view(datasets.get(identity, principal(request).id)))

    @app.post("/api/v1/datasets/{identity}/verify")
    async def verify(identity: str, request: Request):
        result = await datasets.inputs(identity, principal(request).id)
        return {"id": identity, "manifest_digest": result["manifest_digest"], "verified": True}
