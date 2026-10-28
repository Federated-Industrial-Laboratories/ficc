# SPDX-License-Identifier: Apache-2.0
"""Pair, grant, invoke and transfer through the normal authenticated FICC interface."""
import asyncio
from typing import Annotated

from fastapi import Request
from fastapi.responses import Response, StreamingResponse
from pydantic import Field

from ..errors import Failure
from ..execution.spec import Identity
from ..schema import Model
from . import artifacts, pairing
from .schema import Approval, Configuration, GrantSpec, Pair


class Remote(Model):
    operation: Annotated[str, Field(min_length=1, max_length=64)]
    body: dict
    id: Identity | None = None


class Transfer(Model):
    model: Identity


class Selection(Model):
    grant: Identity | None = None


async def connected(request, operation):
    stopping = False
    async def watch():
        while not stopping and not await request.is_disconnected():
            await asyncio.sleep(0.1)
    pending = asyncio.create_task(operation)
    disconnected = asyncio.create_task(watch())
    delivered = False
    try:
        done, _ = await asyncio.wait((pending, disconnected), return_when=asyncio.FIRST_COMPLETED)
        if disconnected in done:
            raise Failure("federation_cancelled", "The HTTP caller disconnected before the remote response.", 499)
        result = await pending
        delivered = True
        return result
    finally:
        # ASGI receive can suppress cancellation inside its own cancel scope.
        # A completed request must still stop its disconnect watcher.
        stopping = True
        pending.cancel()
        disconnected.cancel()
        await asyncio.gather(pending, disconnected, return_exceptions=True)
        if not delivered and not pending.cancelled() and pending.exception() is None:
            _, stream = pending.result()
            if stream is not None:
                await stream.aclose()


def install(app, service, principal):
    manager = service.federation

    @app.get("/api/v1/federation")
    async def overview(request: Request):
        actor = principal(request, "federation:read")
        offers = [value for value in manager.offers.all() if value["project_id"] == actor.project_id
                  or actor.local_owner and value["direction"] == "incoming" and value["state"] == "pending"]
        return {**await manager.status(actor), "peers": manager.peers.all(actor.project_id),
                "offers": offers, "grants": manager.grants.all(actor.project_id),
                "transfers": [artifacts.view(v) for v in manager.transfers.values() if v["project_id"] == actor.project_id]}

    @app.put("/api/v1/federation/configuration")
    async def configure(body: Configuration, request: Request):
        return await manager.configure(body, principal(request, "federation:manage"))

    @app.post("/api/v1/federation/offers")
    async def offer(body: Pair, request: Request):
        return await pairing.start(manager, body.service, body.requested, principal(request, "federation:manage"))

    @app.post("/api/v1/federation/offers/{identity}/approve")
    async def approve(identity: str, body: Approval, request: Request):
        return pairing.approve(manager, identity, body, principal(request, "federation:manage"))

    @app.post("/api/v1/federation/offers/{identity}/finish")
    async def finish(identity: str, request: Request):
        return await pairing.finish(manager, identity, principal(request, "federation:manage"))

    @app.delete("/api/v1/federation/offers/{identity}")
    async def discard(identity: str, request: Request):
        actor = manager.current(principal(request, "federation:manage"), "federation:manage")
        value = manager.offers.get(identity)
        actor.require_record(value)
        if value["state"] not in {"pending", "suspended"}:
            raise Failure("pairing_active", "Remove the peer relationship before discarding an accepted offer.", 409)
        manager.offers.remove(identity)
        return {"removed": True}

    @app.delete("/api/v1/federation/peers/{identity}")
    async def remove(identity: str, request: Request):
        return await manager.remove(identity, principal(request, "federation:manage"))

    @app.post("/api/v1/federation/peers/{identity}/grants")
    async def grant(identity: str, body: GrantSpec, request: Request):
        actor = manager.current(principal(request, "federation:manage"), "federation:manage")
        peer = manager.peers.get(identity)
        actor.require_record(peer)
        if peer["state"] != "paired":
            raise Failure("pairing_inactive", "Complete pairing before issuing another grant.", 409)
        return manager.authority.create(peer, body, actor)

    @app.post("/api/v1/federation/peers/{identity}/forget")
    async def forget(identity: str, request: Request):
        return await manager.forget(identity, principal(request, "federation:manage"))

    @app.post("/api/v1/federation/grants/{identity}/retire")
    async def retire(identity: str, request: Request):
        return await manager.retire(identity, principal(request, "federation:manage"))

    @app.delete("/api/v1/federation/grants/{identity}")
    async def revoke(identity: str, request: Request):
        return await manager.authority.revoke(identity, principal(request, "federation:manage"))

    @app.post("/api/v1/federation/peers/{identity}/refresh")
    async def refresh(identity: str, body: Selection, request: Request):
        return await manager.refresh_grants(identity, principal(request, "federation:manage"), body.grant)

    @app.post("/api/v1/federation/peers/{identity}/request")
    async def remote(identity: str, body: Remote, request: Request):
        actor = principal(request, "federation:invoke")
        if body.operation in {"inference.create", "inference.replace", "inference.control", "models.create", "models.remove"} and body.id is None:
            raise Failure("operation_id_required", "Supply and retain an operation ID before a remote mutation.", 422)
        if body.operation.startswith("pair."):
            raise Failure("federation_operation", "Use the pairing workflow for pairing operations.", 422)
        result, chunks = await connected(request, manager.client.request(identity, body.operation, body.body, actor, body.id))
        if chunks is None:
            return result
        return StreamingResponse(chunks, media_type="application/octet-stream", headers={"X-Accel-Buffering": "no"})

    @app.get("/api/v1/federation/peers/{identity}/v1/models")
    async def models(identity: str, request: Request):
        actor = principal(request, "federation:invoke")
        value, _ = await manager.client.request(identity, "discover", {}, actor)
        return {"object": "list", "data": [{"id": item["id"], "object": "model", "owned_by": "ficc-peer",
                "alias": item["alias"], "capabilities": item["capabilities"]} for item in value["services"]]}

    @app.post("/api/v1/federation/peers/{identity}/v1/{operation:path}")
    async def invoke(identity: str, operation: str, request: Request):
        actor = principal(request, "federation:invoke")
        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get("model"), str):
            raise Failure("federation_model", "Select a published remote service ID as the model.", 422)
        result, chunks = await connected(request, manager.client.request(identity, "inference.invoke", {
            "service": body["model"], "path": "/v1/"+operation, "body": body}, actor))
        if chunks is None:
            raise Failure("federation_protocol", "The peer did not return an inference stream.", 502)
        if body.get("stream") is True:
            return StreamingResponse(chunks, status_code=result["status"], media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})
        data = bytearray()
        try:
            async for chunk in chunks:
                data.extend(chunk)
                if len(data) > 2*1024*1024:
                    raise Failure("federation_response_limit", "Use streaming for responses larger than 2 MiB.", 502)
        finally:
            await chunks.aclose()
        return Response(bytes(data), status_code=result["status"], media_type="application/json")

    @app.post("/api/v1/federation/peers/{identity}/models", status_code=202)
    async def acquire(identity: str, body: Transfer, request: Request):
        return artifacts.start(manager, identity, body.model, principal(request, "federation:invoke"))

    @app.post("/api/v1/federation/transfers/{identity}/pause")
    async def pause(identity: str, request: Request):
        actor = manager.current(principal(request, "federation:invoke"), "federation:invoke")
        value = manager.transfers.get(identity)
        if value is None or value["project_id"] != actor.project_id:
            raise Failure("not_found", "The federation transfer was not found.", 404)
        value["task"].cancel()
        await asyncio.gather(value["task"], return_exceptions=True)
        return artifacts.view(value)
