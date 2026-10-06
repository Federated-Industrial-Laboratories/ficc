# SPDX-License-Identifier: Apache-2.0
"""Disclose approved cached observations with current authority and durable audit."""

import json
import re

from fastapi import Request
from pydantic import ValidationError

from .errors import Failure
from .observation_schema import NODE_ID, Inventory, InventoryNode, Reading

RESOURCE_PATH = re.compile(r"/api/v1/observations/nodes/[A-Za-z0-9][A-Za-z0-9_-]{0,79}/resources\Z")


def observation_token(value, store):
    if value.kind != "token":
        return False
    # Membership attenuation must not hide a broader original credential ceiling.
    with store.lock:
        row = store.db.execute("SELECT scopes FROM credentials WHERE id=:p0", (value.id,)).fetchone()
    if row is None:
        raise Failure("unauthenticated", "Sign in to continue.", 401)
    scopes = json.loads(row[0])
    return bool(scopes) and not set(scopes) - {"observations:read", "observations:resources"}


def audit(store, value, action, target, outcome):
    try:
        store.audit(action, target, outcome, actor=value.id,
                    subject_id=value.subject_id, project_id=value.project_id)
    except Exception:
        raise Failure("audit_unavailable", "The observation could not be recorded.", 503) from None


def restrict_request(request, value, store):
    if observation_token(value, store) and not (
        request.method == "GET" and (request.url.path == "/api/v1/observations/nodes"
                                     or RESOURCE_PATH.fullmatch(request.url.path))
    ):
        audit(store, value, "observation.request", "unsupported_request", "denied")
        raise Failure("observation_boundary", "This credential permits only observation requests.", 403)


def install(app, service, principal):
    @app.get("/api/v1/observations/nodes")
    async def nodes(request: Request):
        with service.store.lock:
            value = principal(request)
            action = "observation.nodes"
            try:
                if not observation_token(value, service.store):
                    raise Failure("observation_credential", "Use a token limited to observation permissions.", 403)
                value.require("observations:read")
                result = []
                decisions = []
                for node in service.store.nodes():
                    permitted = value.permits("observations:read", node["id"])
                    decisions.append((node["id"], "allowed" if permitted else "denied"))
                    if permitted:
                        view = service.view(node)
                        result.append(InventoryNode.model_validate(
                            {key: view[key] for key in InventoryNode.model_fields}))
                payload = Inventory(nodes=result).model_dump()
            except Failure:
                audit(service.store, value, action, "nodes", "denied")
                raise
            except (ValidationError, KeyError, TypeError):
                audit(service.store, value, action, "nodes", "denied")
                raise Failure("observation_invalid", "The stored observation is invalid.", 503) from None
            for target, outcome in decisions:
                audit(service.store, value, action, target, outcome)
            audit(service.store, value, action, "nodes", "allowed")
            return payload

    @app.get("/api/v1/observations/nodes/{node_id}/resources")
    async def resources(node_id: str, request: Request):
        with service.store.lock:
            value = principal(request)
            action = "observation.resources"
            target = node_id if NODE_ID.fullmatch(node_id) else "invalid"
            try:
                if not observation_token(value, service.store):
                    raise Failure("observation_credential", "Use a token limited to observation permissions.", 403)
                if not NODE_ID.fullmatch(node_id):
                    raise Failure("invalid_node", "Select a valid machine identity.", 422)
                for scope in ("observations:read", "observations:resources"):
                    value.require(scope, node_id)
                view = service.view(service.store.node(node_id))
                payload = Reading.model_validate({"node_id": node_id, **{
                    key: view[key] for key in Reading.model_fields if key != "node_id"}}).model_dump()
            except Failure:
                audit(service.store, value, action, target, "denied")
                raise
            except (ValidationError, KeyError, TypeError):
                audit(service.store, value, action, target, "denied")
                raise Failure("observation_invalid", "The stored observation is invalid.", 503) from None
            # This records allowed disclosure, not receipt by a remote consumer.
            audit(service.store, value, action, target, "allowed")
            return payload
