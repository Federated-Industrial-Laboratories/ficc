# SPDX-License-Identifier: Apache-2.0
"""Expose current dataset safety and explicitly authorised local inspection."""

from fastapi import Query, Request

from .file_numbers import wire
from .inspection_schema import Exemption, InspectionConfig, SafetyChange


def install(app, service, principal):
    inspections, safety = service.inspections, service.datasets.safety

    @app.get("/api/v1/inspection-settings")
    async def settings(request: Request):
        return wire(inspections.settings(principal(request).id))

    @app.put("/api/v1/inspection-settings")
    async def configure(body: InspectionConfig, request: Request):
        return wire(inspections.configure(body.model_dump(), principal(request).id))

    @app.get("/api/v1/datasets/{identity}/safety")
    async def status(identity: str, request: Request):
        return wire(safety.effective(service.datasets.get(identity, principal(request).id)))

    @app.put("/api/v1/datasets/{identity}/safety")
    async def update(identity: str, body: SafetyChange, request: Request):
        return wire(safety.update(identity, body.model_dump(), principal(request).id))

    @app.put("/api/v1/datasets/{identity}/exemption")
    async def exempt(identity: str, body: Exemption, request: Request):
        return wire(safety.update(identity, body.model_dump(), principal(request).id, exemption=True))

    @app.post("/api/v1/datasets/{identity}/inspections", status_code=202)
    async def start(identity: str, request: Request):
        return wire(await inspections.submit(identity, request.headers.get("idempotency-key", ""), principal(request).id))

    @app.get("/api/v1/inspections/{identity}")
    async def receipt(identity: str, request: Request):
        return wire(inspections.get(identity, principal(request).id))

    @app.get("/api/v1/inspections/{identity}/files")
    async def files(identity: str, request: Request, after: int = Query(default=-1, ge=-1, le=127)):
        return wire(inspections.files(identity, principal(request).id, after))

    @app.post("/api/v1/inspections/{identity}/cancel")
    async def cancel(identity: str, request: Request):
        return wire(await inspections.cancel(identity, principal(request).id))
