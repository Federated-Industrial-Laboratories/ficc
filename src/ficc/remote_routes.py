# SPDX-License-Identifier: Apache-2.0
"""Expose bound external sign-in and local-owner identity approval."""

import time
from typing import Annotated

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import Field

from .errors import Failure
from .schema import Model
from .workspace_schema import Identity, Revision

LOGIN_COOKIE = "__Host-ficc_login"


def session_cookie(response, cookie, credential, expires, remote):
    response.set_cookie(cookie, credential, max_age=max(1, int(expires - time.time())),
                        secure=remote, httponly=True, samesite="strict", path="/")


class Mapping(Model):
    issuer: Annotated[str, Field(min_length=1, max_length=2048)]
    external_subject: Annotated[str, Field(min_length=1, max_length=255)]
    subject_id: Identity
    disabled: bool = False
    revision: Revision


def install(app, service, principal, cookie):
    host = service.remote_auth

    def owner(request):
        value = principal(request)
        value.require_host("identities:manage")
        if not value.local_owner or value.node_ids is not None or value.root_ids is not None:
            raise Failure("denied", "Local owner identity administration is required.", 403)
        return value

    @app.get("/api/v1/login")
    async def status():
        return host.status()

    @app.post("/auth/start")
    async def begin(request: Request):
        if service.settings.remote is None or request.headers.get("origin") != service.settings.origin:
            raise Failure("invalid_origin", "Start sign-in from the configured remote console.", 403)
        url, browser = await host.begin()
        response = JSONResponse({"url": url})
        response.set_cookie(LOGIN_COOKIE, browser, max_age=300, secure=True, httponly=True, samesite="lax", path="/")
        return response

    @app.get("/auth/callback")
    async def callback(request: Request):
        if service.settings.remote is None:
            raise Failure("not_found", "Remote sign-in is not enabled.", 404)
        try:
            items = request.query_params.multi_items()
            value = dict(items)
            if (len(items) != len(value) or set(value) - {"code", "state", "iss", "session_state", "error", "error_description"}
                    or not 32 <= len(value.get("state", "")) <= 128
                    or not 1 <= len(value.get("code", "")) <= 4096 or "error" in value):
                raise Failure("login_invalid", "The sign-in return is invalid.", 401)
            secret, principal_value = await host.complete(value["state"], value["code"],
                                            request.cookies.get(LOGIN_COOKIE, ""), value.get("iss"))
            response = RedirectResponse("/", status_code=303)
            session_cookie(response, cookie, secret, principal_value.expires_at, True)
        except Failure as exc:
            selected = "unapproved" if exc.code == "identity_unapproved" else "failed"
            service.store.audit("session.external", "login", outcome=selected)
            response = RedirectResponse("/?login=" + selected, status_code=303)
        response.delete_cookie(LOGIN_COOKIE, secure=True, httponly=True, samesite="lax", path="/")
        return response

    @app.get("/api/v1/external-identities")
    async def mappings(request: Request):
        owner(request)
        return {"mappings": host.records.all(), "provider": host.status()}

    @app.put("/api/v1/external-identities")
    async def approve(body: Mapping, request: Request):
        actor = owner(request)
        return host.records.save(body.issuer, body.external_subject, body.subject_id, body.disabled, body.revision, actor)
