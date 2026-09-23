# SPDX-License-Identifier: Apache-2.0
"""Expose scoped operation and helper-upgrade routes."""

from typing import Annotated, Literal

from fastapi import Query, Request

from .errors import Failure
from .job_schema import Cancellation, HelperUpgrade, JobRequest, Submission


def install(app, service, principal):
    jobs = service.jobs

    @app.post("/api/v1/operation-previews")
    async def preview(body: JobRequest, request: Request):
        actor = principal(request, "jobs:execute")
        return await jobs.preview(body.model_dump(), actor.id)

    @app.post("/api/v1/operations", status_code=202)
    async def submit(body: Submission, request: Request):
        actor = principal(request, "jobs:execute")
        result = await jobs.submit(body.preview_id, request.headers.get("idempotency-key", ""), actor.id)
        return jobs.view(result, actor)

    @app.get("/api/v1/operations")
    async def operations(request: Request):
        actor = principal(request, "jobs:read")
        visible = [jobs.view(operation, actor) for operation in jobs.store.all()]
        return {"operations": [operation for operation in visible if operation["targets"]][:200]}

    @app.get("/api/v1/operations/{operation_id}")
    async def operation(operation_id: str, request: Request):
        actor = principal(request, "jobs:read")
        result = jobs.view(jobs.store.get(operation_id), actor)
        if not result["targets"]:
            raise Failure("not_found", "The operation was not found.", 404)
        return result

    @app.post("/api/v1/operations/{operation_id}/cancel", status_code=202)
    async def cancel(operation_id: str, body: Cancellation, request: Request):
        actor = principal(request, "jobs:cancel")
        result = await jobs.cancel(operation_id, body.node_ids, body.force, actor.id)
        return jobs.view(result, actor)

    @app.get("/api/v1/operations/{operation_id}/logs/{node_id}")
    async def logs(operation_id: str, node_id: str, request: Request,
                   stream: Literal["stdout", "stderr"] = "stdout",
                   offset: Annotated[int, Query(ge=0, le=2**63 - 1)] = 0,
                   limit: Annotated[int, Query(ge=1, le=65536)] = 65536):
        actor = principal(request, "jobs:logs", node_id)
        return await jobs.logs(operation_id, node_id, stream, offset, limit, actor.id)

    @app.post("/api/v1/nodes/{node_id}/helper-upgrade")
    async def upgrade(node_id: str, body: HelperUpgrade, request: Request):
        actor = principal(request, "nodes:write", node_id)
        return await service.upgrade(node_id, body.expected_fingerprint, actor.id)
