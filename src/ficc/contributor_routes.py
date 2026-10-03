# SPDX-License-Identifier: Apache-2.0
"""Separate project administration, invitation claims and authenticated node channels."""

import asyncio
import json

from fastapi import Request, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from .contributor_schema import Approval, Claim, Disable, Heartbeat, Invitation, Receipt, Rotation
from .errors import Failure
from .workspace_schema import Identity


def node_fingerprint(request):
    value = request.scope.get("state", {}).get("ficc_node_fingerprint")
    if not value:
        raise Failure("node_gateway_required", "Use the authenticated contributor gateway.", 403)
    return value


def install(app, service, principal):
    nodes = service.contributors

    @app.get("/api/v1/contributors")
    async def all_nodes(request: Request):
        return nodes.all(principal(request, "contributors:read"))

    @app.post("/api/v1/contributor-invitations", status_code=201)
    async def invite(body: Invitation, request: Request):
        return nodes.invite(body.name, body.mode, principal(request, "contributors:manage"))

    @app.post("/api/v1/contributor-requests/{identity}/approve")
    async def approve(identity: Identity, body: Approval, request: Request):
        actor = principal(request, "contributors:manage")
        result = await nodes.issue(identity, body.public_key, body.revision, actor)
        return {key: result[key] for key in ("id", "node_id", "status", "revision")}

    @app.post("/api/v1/contributors/{identity}/disable")
    async def disable(identity: Identity, body: Disable, request: Request):
        return await nodes.disable(identity, body.revision, principal(request, "contributors:manage"))

    @app.post("/api/v1/contributors/{identity}/remove")
    async def remove(identity: Identity, body: Disable, request: Request):
        return nodes.remove(identity, body.revision, principal(request, "contributors:manage"))

    @app.post("/api/v1/node-enrollment/claim", status_code=201)
    async def claim(body: Claim):
        try:
            return nodes.claim(body.secret, body.csr_pem, body.node_id)
        except (ValueError, TypeError):
            raise Failure("invalid_request", "The signed node enrollment request is invalid.") from None

    @app.post("/api/v1/node-enrollment/status")
    async def receipt(body: Receipt):
        nodes.configured()
        return nodes.records.receipt(body.request_id, body.receipt)

    @app.post("/api/v1/node-channel/activate")
    async def activate(request: Request):
        return await nodes.activate(node_fingerprint(request))

    @app.post("/api/v1/node-channel/rotate")
    async def rotate(body: Rotation, request: Request):
        try:
            return await nodes.rotate(node_fingerprint(request), body.request_id, body.csr_pem)
        except (ValueError, TypeError):
            raise Failure("invalid_request", "The signed key rotation request is invalid.") from None

    @app.post("/api/v1/node-channel/poll")
    async def poll(body: Heartbeat, request: Request):
        return nodes.heartbeat(node_fingerprint(request), body, "polling")

    @app.websocket("/api/v1/node-channel/stream")
    async def stream(websocket: WebSocket):
        session_id = None
        try:
            nodes.configured()
            fingerprint = node_fingerprint(websocket)
            node, _ = nodes.records.authenticate(fingerprint)
            await websocket.accept()
            while True:
                try:
                    async with asyncio.timeout(1 if session_id else 5):
                        raw = await websocket.receive_text()
                except TimeoutError:
                    if session_id is None:
                        raise Failure("node_timeout", "The contributor handshake timed out.", 408) from None
                    nodes.connection(node["id"], session_id, fingerprint)
                    continue
                if len(raw.encode()) > 16384:
                    raise Failure("request_limit", "The contributor frame exceeds the limit.", 413)
                if session_id:
                    nodes.connection(node["id"], session_id, fingerprint)
                message = Heartbeat.model_validate_json(raw)
                if session_id is not None and message.session_id != session_id:
                    raise Failure("invalid_session", "The contributor stream identity changed.", 403)
                result = nodes.heartbeat(fingerprint, message, "persistent")
                session_id = result["session_id"]
                await websocket.send_text(json.dumps(result, allow_nan=False))
        except WebSocketDisconnect:
            pass
        except (Failure, ValueError, ValidationError, KeyError):
            try:
                await websocket.close(code=4403)
            except (RuntimeError, WebSocketDisconnect):
                pass
