# SPDX-License-Identifier: Apache-2.0
"""Service lifecycle and a documented OpenAI-compatible inference subset."""
import asyncio
import json

from fastapi import Request
from fastapi.responses import Response, StreamingResponse

from ..errors import Failure
from ..schema import Model
from .schema import ServiceSpecification


class Update(Model):
    revision: int
    spec: ServiceSpecification


class Token(Model):
    lifetime: int = 3600


class Control(Model):
    revision: int
    acknowledge_unknown: bool = False



async def connected(request, operation):
    stopping, delivered = False, False
    async def watch():
        while not stopping and not await request.is_disconnected():
            await asyncio.sleep(0.1)
    pending = asyncio.create_task(operation)
    disconnected = asyncio.create_task(watch())
    try:
        try:
            done, _ = await asyncio.wait((pending, disconnected), return_when=asyncio.FIRST_COMPLETED)
            if disconnected in done:
                raise Failure("inference_cancelled", "The HTTP caller disconnected before the inference response.", 499)
            result = await pending
        finally:
            # ASGI receive may suppress cancellation inside its own cancel scope.
            stopping = True
            pending.cancel()
            disconnected.cancel()
            await asyncio.gather(pending, disconnected, return_exceptions=True)
        delivered = True
        return result
    finally:
        if not delivered and pending.done() and not pending.cancelled() and pending.exception() is None:
            _, stream = pending.result()
            if stream is not None:
                await stream.aclose()


class OwnedResponse(StreamingResponse):
    def __init__(self, chunks, **kwargs):
        super().__init__(chunks, **kwargs)
        self.chunks = chunks

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self.chunks.aclose()


async def collect(chunks):
    data = bytearray()
    async for chunk in chunks:
        data.extend(chunk)
        if len(data) > 2 * 1024 * 1024:
            raise Failure("inference_response_limit", "Use streaming for responses larger than 2 MiB.", 502)
    return bytes(data), None


def install(app, service, principal):
    manager = service.inference

    @app.get("/api/v1/inference")
    async def all_services(request: Request):
        actor = principal(request, "inference:read")
        return {"services": [manager.view(value) for value in manager.records.all(actor.project_id)],
                "engines": [*manager.providers.adapters, "attached"], "endpoint_profiles": manager.attached.available(actor)}

    @app.post("/api/v1/inference/preview")
    async def preview(body: ServiceSpecification, request: Request):
        jobs = manager.preview(body, principal(request, "inference:manage"))
        return {"replicas": len(jobs), "jobs": [item.model_dump() for item in jobs],
                "download_bytes": 0, "reserved_bytes": sum(item.job.limits.storage_bytes for item in jobs)}

    @app.post("/api/v1/inference", status_code=202)
    async def create(body: ServiceSpecification, request: Request):
        return await manager.create(body, principal(request, "inference:manage"))

    @app.get("/api/v1/inference/{identity}")
    async def get(identity: str, request: Request):
        return manager.view(manager.get(identity, principal(request, "inference:read")))

    @app.put("/api/v1/inference/{identity}")
    async def replace(identity: str, body: Update, request: Request):
        return await manager.replace(identity, body.spec, body.revision, principal(request, "inference:manage"))

    @app.post("/api/v1/inference/{identity}/control/{operation}")
    async def control(identity: str, operation: str, body: Control, request: Request):
        return await manager.control(identity, operation, body.revision, principal(request, "inference:manage"),
                                     acknowledge_unknown=body.acknowledge_unknown)

    @app.post("/api/v1/inference/{identity}/tokens")
    async def token(identity: str, body: Token, request: Request):
        return manager.token(identity, principal(request, "inference:manage"), body.lifetime)

    @app.get("/api/v1/inference/{identity}/v1/models")
    async def compatible_models(identity: str, request: Request):
        value = manager.get(identity, principal(request, "inference:invoke"), "inference:invoke")
        return {"object": "list", "data": [{"id": value["spec"]["alias"], "object": "model", "created": int(value["created_at"]), "owned_by": "ficc"}]}

    @app.post("/api/v1/inference/{identity}/v1/{operation:path}")
    async def invoke(identity: str, operation: str, request: Request):
        actor = principal(request, "inference:invoke")
        body = await request.json()
        if not isinstance(body, dict):
            raise Failure("inference_request", "The inference body must be a JSON object.", 422)
        status, chunks = await connected(request, manager.gateway.invoke(identity, "/v1/" + operation, body, actor))
        if body.get("stream") is True:
            return OwnedResponse(chunks, status_code=status, media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})
        try:
            data, _ = await connected(request, collect(chunks))
        finally:
            await chunks.aclose()
        try:
            json.loads(data)
        except ValueError:
            raise Failure("inference_protocol", "The engine returned invalid JSON.", 502) from None
        return Response(bytes(data), status_code=status, media_type="application/json")
