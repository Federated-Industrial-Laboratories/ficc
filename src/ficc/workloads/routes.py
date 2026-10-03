# SPDX-License-Identifier: Apache-2.0
"""Expose bounded workload batches, project output reads, and node execution polling."""

from typing import Annotated

from fastapi import Query, Request
from pydantic import Field, model_validator

from ..contributor_routes import node_fingerprint
from ..errors import Failure
from ..execution.spec import Count, Revision, distinct
from ..file_numbers import wire
from ..schema import Model
from .artifacts import Publication
from .channel import Exchange
from .schema import Key, Submission


class Item(Model):
    key: Key
    request: Submission


class Batch(Model):
    requests: Annotated[list[Item], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def keys(self):
        distinct([item.key for item in self.requests])
        return self


class Expected(Model):
    revision: Revision


class Retry(Expected):
    acknowledge_unknown: bool = False


class OutputRead(Model):
    object: Annotated[str, Field(pattern=r"^(stdout|stderr|output:[a-z][a-z0-9_.-]{0,79})$")]
    offset: Count
    length: Annotated[int, Field(ge=1, le=1024 * 1024)]


class Reads(Model):
    reads: Annotated[list[OutputRead], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def bounded(self):
        distinct([(item.object, item.offset) for item in self.reads])
        if sum(item.length for item in self.reads) > 1024 * 1024:
            raise ValueError("Read at most 1 MiB in each output batch.")
        return self


class Suspension(Model):
    suspended: bool


class PublicationCancel(Model):
    discard_partial: bool = False


def install(app, service, principal):
    queue = service.workloads

    @app.get("/api/v1/workloads")
    async def all_workloads(request: Request):
        return queue.all(principal(request, "jobs:read"))

    @app.get("/api/v1/workload-offers")
    async def offers(request: Request):
        return queue.offers(principal(request, "contributors:read"))

    @app.post("/api/v1/workloads", status_code=202)
    async def submit(body: Batch, request: Request):
        actor = principal(request, "jobs:execute")
        results = []
        for item in body.requests:
            try:
                results.append({"key": item.key, "ok": True, "workload": await queue.submit(item.request, item.key, actor)})
            except Failure as exc:
                results.append({"key": item.key, "ok": False, "error": {"code": exc.code, "message": exc.message}})
        return {"results": results}

    @app.get("/api/v1/workloads/{identity}")
    async def get(identity: str, request: Request):
        return queue.view(queue.owned(identity, principal(request, "jobs:read"), "jobs:read"))

    @app.post("/api/v1/workloads/{identity}/cancel", status_code=202)
    async def cancel(identity: str, body: Expected, request: Request):
        return queue.cancel(identity, body.revision, principal(request, "jobs:cancel"))

    @app.post("/api/v1/workloads/{identity}/retry", status_code=202)
    async def retry(identity: str, body: Retry, request: Request):
        return await queue.retry(identity, body.revision, principal(request, "jobs:execute"), acknowledge_unknown=body.acknowledge_unknown)

    @app.post("/api/v1/workloads/{identity}/release")
    async def release(identity: str, body: Expected, request: Request):
        return await queue.release(identity, body.revision, principal(request, "jobs:cancel"))

    @app.post("/api/v1/workloads/{identity}/remove")
    async def remove(identity: str, body: Expected, request: Request):
        return queue.remove(identity, body.revision, principal(request, "jobs:cancel"))

    @app.post("/api/v1/workloads/{identity}/abandon")
    async def abandon(identity: str, body: Retry, request: Request):
        return queue.abandon(identity, body.revision, principal(request, "jobs:cancel"), body.acknowledge_unknown)

    @app.post("/api/v1/workloads/{identity}/output")
    async def output(identity: str, body: Reads, request: Request):
        return await queue.collect(identity, body.reads, principal(request, "jobs:logs"))

    @app.post("/api/v1/workloads/{identity}/artifacts", status_code=202)
    async def publish(identity: str, body: Publication, request: Request):
        return wire(await queue.artifacts.publish(identity, body, request.headers.get("idempotency-key", ""), principal(request, "jobs:logs")))

    @app.get("/api/v1/workloads/{identity}/artifacts")
    async def publications(identity: str, request: Request, before: str | None = Query(default=None, pattern=r"^[a-f0-9]{32}$")):
        return wire(queue.artifacts.all(identity, principal(request, "jobs:logs").id, before))

    @app.get("/api/v1/workloads/{identity}/artifacts/{operation_id}")
    async def publication(identity: str, operation_id: str, request: Request):
        actor = principal(request, "jobs:logs").id
        return wire(queue.artifacts.view(queue.artifacts.selected(identity, operation_id, actor), actor))

    @app.post("/api/v1/workloads/{identity}/artifacts/{operation_id}/resume")
    async def resume_publication(identity: str, operation_id: str, request: Request):
        return wire(await queue.artifacts.change(identity, operation_id, principal(request, "jobs:logs").id, resume=True))

    @app.post("/api/v1/workloads/{identity}/artifacts/{operation_id}/cancel")
    async def cancel_publication(identity: str, operation_id: str, body: PublicationCancel, request: Request):
        return wire(await queue.artifacts.change(identity, operation_id, principal(request, "jobs:logs").id, discard=body.discard_partial))

    @app.post("/api/v1/workload-control")
    async def control(body: Suspension, request: Request):
        actor = principal(request, "policies:manage")
        if not actor.local_owner:
            raise Failure("denied", "Only the installation owner can change dispatch suspension.", 403)
        service.store.set_setting("workloads.suspended", body.suspended)
        queue.audit("workload.suspension", str(body.suspended).lower(), actor)
        return {"suspended": queue.suspended()}

    @app.post("/api/v1/node-channel/execution")
    async def execution(body: Exchange, request: Request):
        try:
            return await queue.channel.exchange(node_fingerprint(request), body)
        except ValueError:
            raise Failure("invalid_executor_response", "The executor response fields are invalid.", 422) from None
