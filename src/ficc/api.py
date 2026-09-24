# SPDX-License-Identifier: Apache-2.0
"""Expose the authenticated local inventory and resource API."""

import asyncio
import secrets
import sqlite3
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from . import __version__
from .auth import Principal
from .control import Control
from .errors import Failure
from .job_routes import install as install_job_routes
from .schema import Bootstrap, EnrolRequest, PreviewRequest, RefreshRequest
from .service import Service
from .settings import MAX_MESSAGE, Settings

COOKIE = "ficc_session"


def failure_response(exc: Failure) -> JSONResponse:
    return JSONResponse({"error": {"code": exc.code, "message": exc.message}}, status_code=exc.status)


def create_app(settings: Settings) -> FastAPI:
    service = Service(settings)
    control = Control(service)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.control:
            await control.start()
        poller = asyncio.create_task(service.poll())
        app.state.poller = poller
        job_poller = asyncio.create_task(service.jobs.poll())
        app.state.job_poller = job_poller
        try:
            yield
        finally:
            poller.cancel()
            job_poller.cancel()
            with suppress(asyncio.CancelledError):
                await job_poller
            await service.jobs.close()
            with suppress(asyncio.CancelledError):
                await poller
            if settings.control:
                await control.close()
            service.store.close()

    app = FastAPI(title="FICC", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.service = service
    origins = {settings.origin, f"http://localhost:{settings.port}"}
    hosts = {origin.removeprefix("http://") for origin in origins}

    @app.middleware("http")
    async def guards(request: Request, call_next):
        try:
            if request.headers.get("host") not in hosts:
                raise Failure("invalid_host", "The request host is not allowed.", 403)
            origin = request.headers.get("origin")
            if origin is not None and origin not in origins:
                raise Failure("invalid_origin", "The request origin is not allowed.", 403)
            if request.headers.get("sec-fetch-site") == "cross-site":
                raise Failure("invalid_origin", "Cross-site requests are not allowed.", 403)
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                content_length = request.headers.get("content-length", "0")
                if not content_length.isdigit() or int(content_length) > MAX_MESSAGE:
                    raise Failure("request_limit", "The request exceeds the limit.", 413)
                data = bytearray()
                async with asyncio.timeout(5):
                    async for chunk in request.stream():
                        data.extend(chunk)
                        if len(data) > MAX_MESSAGE:
                            raise Failure("request_limit", "The request exceeds the limit.", 413)
                request._body = bytes(data)
            response = await call_next(request)
        except Failure as exc:
            response = failure_response(exc)
        except TimeoutError:
            response = failure_response(Failure("request_timeout", "The request timed out.", 408))
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.exception_handler(Failure)
    async def failed(request: Request, exc: Failure):
        return failure_response(exc)

    @app.exception_handler(sqlite3.Error)
    async def storage_failed(request: Request, exc: sqlite3.Error):
        return failure_response(Failure("storage_unavailable", "Local state could not be saved or read.", 503))

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError):
        return failure_response(Failure("invalid_request", "The request fields are invalid.", 422))

    @app.exception_handler(HTTPException)
    async def http_failed(request: Request, exc: HTTPException):
        return failure_response(Failure("not_found" if exc.status_code == 404 else "request_failed",
                                        "The request could not be completed.", exc.status_code))

    def principal(request: Request, scope: str | None = None, node_id: str | None = None) -> Principal:
        authorization = request.headers.get("authorization")
        if authorization:
            if not authorization.startswith("Bearer "):
                raise Failure("unauthenticated", "Use a bearer credential.", 401)
            result = service.auth.resolve(authorization[7:], ("token",))
        else:
            result = service.auth.resolve(request.cookies.get(COOKIE, ""), ("session",))
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                if request.headers.get("origin") not in origins or not secrets.compare_digest(
                    result.csrf, request.headers.get("x-csrf-token", "")
                ):
                    raise Failure("csrf_denied", "The session request check failed.", 403)
        if scope:
            result.require(scope, node_id)
        return result

    def unrestricted(value: Principal) -> None:
        if value.node_ids is not None:
            raise Failure("denied", "An unrestricted credential is required.", 403)

    def session(value: Principal) -> dict:
        return {"version": __version__, "mode": "demo" if settings.demo else "live",
                "csrf": value.csrf, "principal": value.public()}

    def visible(node: dict, value: Principal) -> dict:
        result = service.view(node)
        if "resources:read" not in value.scopes:
            result["resources"] = None
        return result

    @app.get("/api/v1/health")
    async def health():
        poller = getattr(app.state, "poller", None)
        job_poller = getattr(app.state, "job_poller", None)
        failed = service.poll_error or service.jobs.failed or (not settings.demo and (
            (poller is not None and poller.done()) or (job_poller is not None and job_poller.done())))
        return {"status": "degraded" if failed else "ok", "version": __version__}

    @app.post("/api/v1/session")
    async def login(body: Bootstrap, request: Request):
        if request.headers.get("origin") not in origins:
            raise Failure("invalid_origin", "Sign in from the local console.", 403)
        service.auth.resolve(body.bootstrap, ("bootstrap",), consume=True)
        credential, value = service.auth.issue("session", lifetime=28800)
        response = JSONResponse(session(value))
        response.set_cookie(COOKIE, credential, max_age=28800, httponly=True, samesite="strict", path="/")
        service.store.audit("session.create", value.id, actor=value.id)
        return response

    @app.get("/api/v1/session")
    async def get_session(request: Request):
        return session(principal(request))

    @app.delete("/api/v1/session")
    async def logout(request: Request):
        value = principal(request)
        service.auth.revoke(value.id, actor=value.id)
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict")
        return response

    @app.get("/api/v1/nodes")
    async def nodes(request: Request):
        value = principal(request, "nodes:read")
        return {"nodes": [visible(node, value) for node in service.store.nodes()
                          if value.node_ids is None or node["id"] in value.node_ids]}

    @app.get("/api/v1/nodes/{node_id}")
    async def node(node_id: str, request: Request):
        value = principal(request, "nodes:read", node_id)
        return visible(service.store.node(node_id), value)

    @app.get("/api/v1/nodes/{node_id}/resources")
    async def resources(node_id: str, request: Request):
        principal(request, "resources:read", node_id)
        value = service.view(service.store.node(node_id))
        return {"node_id": node_id, **{key: value[key] for key in ("resources", "last_seen", "stale")}}

    @app.post("/api/v1/nodes/refresh")
    async def refresh(body: RefreshRequest, request: Request):
        value = principal(request, "resources:read")
        value.require("nodes:read")
        for node_id in body.node_ids:
            value.require("resources:read", node_id)
        return {"nodes": await service.refresh(body.node_ids, actor=value.id)}

    @app.get("/api/v1/profiles")
    async def profiles(request: Request):
        unrestricted(principal(request, "nodes:write"))
        return {"profiles": [{"id": profile, "label": profile} for profile in service.profiles]}

    @app.post("/api/v1/node-previews")
    async def preview(body: PreviewRequest, request: Request):
        value = principal(request, "nodes:write")
        unrestricted(value)
        return await service.preview(body.profile, body.name, value.id)

    @app.post("/api/v1/nodes")
    async def enroll(body: EnrolRequest, request: Request):
        value = principal(request, "nodes:write")
        unrestricted(value)
        result = await service.enroll(body.preview_id, body.expected_fingerprint, body.install_helper, value.id)
        if "resources:read" not in value.scopes:
            result["resources"] = None
        return result

    @app.delete("/api/v1/nodes/{node_id}")
    async def forget(node_id: str, request: Request):
        value = principal(request, "nodes:write", node_id)
        service.live()
        service.store.node(node_id)
        unrestricted(value)
        if service.jobs.store.active(node_id):
            raise Failure("node_busy", "Resolve active or unknown jobs before forgetting this machine.", 409)
        service.store.delete_node(node_id)
        service.store.audit("node.forget", node_id, actor=value.id)
        if node_id in service.locks and not service.locks[node_id].locked():
            service.locks.pop(node_id)
        return {"ok": True}

    @app.get("/api/v1/permissions")
    async def permissions(request: Request):
        value = principal(request)
        return {"scopes": value.scopes, "node_ids": value.node_ids}

    @app.get("/api/v1/tokens")
    async def tokens(request: Request):
        unrestricted(principal(request, "tokens:manage"))
        return {"tokens": service.auth.tokens()}

    @app.delete("/api/v1/tokens/{token_id}")
    async def revoke(token_id: str, request: Request):
        value = principal(request, "tokens:manage")
        unrestricted(value)
        service.auth.revoke(token_id, actor=value.id)
        return {"ok": True}

    @app.get("/api/v1/audit")
    async def audit(request: Request):
        unrestricted(principal(request, "audit:read"))
        return {"events": service.store.events()}

    install_job_routes(app, service, principal)

    static = Path(__file__).parent / "static"
    if static.is_dir():
        app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    async def index():
        if not (static / "index.html").is_file():
            raise Failure("assets_missing", "The console assets are not installed.", 503)
        return FileResponse(static / "index.html")

    return app
