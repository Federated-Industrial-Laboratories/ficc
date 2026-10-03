# SPDX-License-Identifier: Apache-2.0
"""Expose owner operational status and bounded authenticated exports."""

import asyncio
from typing import Annotated

from fastapi import Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .operations import Operations


def install(app, service, principal):
    operations = Operations(service)

    @app.get("/api/v1/operational-status")
    async def health(request: Request):
        return await asyncio.to_thread(operations.health, principal(request).id)

    @app.get("/api/v1/operational-status/diagnostics")
    async def diagnostics(request: Request):
        actor = principal(request).id
        value = await asyncio.to_thread(operations.diagnostics, actor)
        service.store.audit("operations.diagnostics", "installation", actor=actor)
        return JSONResponse(value, headers={"Content-Disposition": 'attachment; filename="ficc-diagnostics.json"'})

    @app.get("/api/v1/operational-status/audit")
    async def audit(request: Request, after: Annotated[int, Query(ge=0, le=2**63 - 1)] = 0):
        actor = principal(request).id
        operations.authorize(actor)
        through = operations.audit_bounds()["last_id"] or 0
        return StreamingResponse(operations.export_audit(actor, after, through), media_type="application/x-ndjson",
            headers={"Content-Disposition": 'attachment; filename="ficc-audit.ndjson"'})
