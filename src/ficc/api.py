# SPDX-License-Identifier: Apache-2.0
"""Expose the authenticated local inventory and resource API."""

import asyncio
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from . import __version__
from .agent_routes import install as install_agent_routes
from .auth import Principal
from .control import Control
from .dataset_routes import install as install_dataset_routes
from .errors import Failure
from .file_routes import install as install_file_routes
from .identity_routes import install as install_identity_routes
from .inspection_routes import install as install_inspection_routes
from .job_routes import install as install_job_routes
from .module_adapter_routes import install as install_adapter_profiles
from .module_admin_routes import install as install_module_administration
from .module_containers_routes import install as install_module_containers
from .module_editor import install as install_module_editor
from .module_editor_store import retained as editor_retained
from .module_routes import install as install_module_routes
from .module_vm_routes import install as install_module_vms
from .module_windows_routes import install as install_windows_endpoints
from .operation_routes import install as install_operation_routes
from .policy_routes import install as install_policy_routes
from .remote_ingress import RemoteIngress
from .remote_routes import install as install_remote_routes
from .remote_routes import session_cookie
from .schema import Bootstrap, EnrolRequest, PreviewRequest, RefreshRequest
from .service import Service
from .settings import MAX_MESSAGE, Settings
from .source_routes import install as install_source_routes
from .terminal_routes import install as install_terminal_routes
from .transfer_routes import install as install_transfer_routes
from .viewer_routes import install as install_viewers
from .workspace_routes import install as install_workspace_routes

COOKIE = "ficc_session"


def failure_response(exc: Failure) -> JSONResponse:
    return JSONResponse({"error": {"code": exc.code, "message": exc.message}}, status_code=exc.status)


def create_app(settings: Settings, *, close_ingress=None) -> FastAPI:
    service = Service(settings)
    control = Control(service)
    cookie = "__Host-ficc_session" if settings.remote else COOKIE

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks: list[asyncio.Task] = []
        try:
            await service.remote_auth.start()
            await service.contributors.start()
            tasks.append(asyncio.create_task(service.remote_auth.poll()))
            tasks.append(asyncio.create_task(service.contributors.poll()))
            tasks.append(asyncio.create_task(service.workloads.runner.poll()))
            service.audit_delivery.start()
            if settings.control:
                await control.start()
            for name, run in (("poller", service.poll), ("job_poller", service.jobs.poll),
                              ("transfer_poller", service.transfers.poll), ("file_poller", service.files.poll),
                              ("agent_poller", service.agents.poll)):
                task = asyncio.create_task(run())
                tasks.append(task)
                setattr(app.state, name, task)
            yield
        finally:
            try:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await service.workloads.inputs.close()
                await service.sources.close()
                await service.audit_delivery.close()
                await service.inspections.close()
                await service.transfers.close()
                await service.files.close()
                await service.jobs.close()
                await service.terminals.close()
                await service.viewers.close()
                await service.adapter_vms.close()
                await service.containers.close()
                await service.administration.close()
                await service.adapters.stop()
                await service.windows.close()
                await service.module_runtime.stop()
                if settings.control:
                    await control.close()
            finally:
                try:
                    await service.ssh.close()
                finally:
                    try:
                        service.close()
                    finally:
                        if close_ingress is not None:
                            close_ingress()

    app = FastAPI(title="FICC", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.service = service
    origins = {settings.origin} if settings.remote else {settings.origin, f"http://localhost:{settings.port}"}
    from urllib.parse import urlsplit
    hosts = {urlsplit(origin).netloc for origin in origins}
    package_uploads = 0

    @app.middleware("http")
    async def guards(request: Request, call_next):
        nonlocal package_uploads
        package_slot = False
        try:
            if request.headers.get("host") not in hosts:
                raise Failure("invalid_host", "The request host is not allowed.", 403)
            origin = request.headers.get("origin")
            callback = settings.remote is not None and request.method == "GET" and request.url.path == "/auth/callback"
            # An external login redirect keeps its cross-site marker on the public document.
            landing = (settings.remote is not None and request.method == "GET" and request.url.path == "/"
                       and request.headers.get("sec-fetch-mode") == "navigate"
                       and request.headers.get("sec-fetch-dest") == "document")
            if origin is not None and origin not in origins and not callback:
                raise Failure("invalid_origin", "The request origin is not allowed.", 403)
            if request.headers.get("sec-fetch-site") == "cross-site" and not (callback or landing):
                raise Failure("invalid_origin", "Cross-site requests are not allowed.", 403)
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                if request.url.path == "/api/v1/module-install-previews":
                    principal(request, "modules:manage")
                    if package_uploads >= 2:
                        raise Failure("capacity", "Wait for a package upload to finish.", 429)
                    package_uploads += 1
                    package_slot = True
                maximum = 16 * 1024 * 1024 if request.url.path == "/api/v1/module-install-previews" else MAX_MESSAGE
                if request.url.path == "/api/v1/workloads":
                    principal(request, "jobs:execute")
                    maximum = 8 * 1024 * 1024
                elif request.url.path == "/api/v1/node-channel/execution":
                    from .contributor_routes import node_fingerprint
                    service.contributors.records.authenticate(node_fingerprint(request))
                    maximum = 3 * 1024 * 1024
                content_length = request.headers.get("content-length", "0")
                if not content_length.isdigit() or int(content_length) > maximum:
                    raise Failure("request_limit", "The request exceeds the limit.", 413)
                data = bytearray()
                async with asyncio.timeout(5):
                    async for chunk in request.stream():
                        data.extend(chunk)
                        if len(data) > maximum:
                            raise Failure("request_limit", "The request exceeds the limit.", 413)
                request._body = bytes(data)
            response = await call_next(request)
        except Failure as exc:
            response = failure_response(exc)
        except TimeoutError:
            response = failure_response(Failure("request_timeout", "The request timed out.", 408))
        finally:
            if package_slot:
                package_uploads -= 1
        websocket_origins = " ".join(origin.replace("https://", "wss://").replace("http://", "ws://") for origin in origins)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "style-src-elem 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; font-src 'self'; "
            f"img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' {websocket_origins}; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        if settings.remote:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    app.add_middleware(RemoteIngress, settings=settings)

    @app.exception_handler(Failure)
    async def failed(request: Request, exc: Failure):
        return failure_response(exc)

    @app.exception_handler(sqlite3.Error)
    async def storage_failed(request: Request, exc: sqlite3.Error):
        return failure_response(Failure("storage_unavailable", "Controller state could not be saved or read.", 503))

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
            result = service.auth.resolve(request.cookies.get(cookie, ""), ("session",))
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                if request.headers.get("origin") not in origins or not secrets.compare_digest(
                    result.csrf, request.headers.get("x-csrf-token", "")
                ):
                    raise Failure("csrf_denied", "The session request check failed.", 403)
        selected = request.headers.get("x-ficc-project")
        if selected is not None and selected != result.project_id:
            raise Failure("project_changed", "This window belongs to another project. Open a new console window.", 409)
        selected_session = request.headers.get("x-ficc-session")
        if selected_session is not None and selected_session != result.id:
            raise Failure("session_changed", "The session changed in another window. Open a new console window.", 409)
        if scope:
            result.require(scope, node_id)
        return result

    def unrestricted(value: Principal) -> None:
        if value.node_ids is not None:
            raise Failure("denied", "An unrestricted credential is required.", 403)

    def session(value: Principal) -> dict:
        return {"version": __version__, "mode": "demo" if settings.demo else "live",
                "remote": settings.remote is not None,
                "expires_at": value.expires_at,
                "csrf": value.csrf, "principal": value.public(),
                "identity": service.auth.identities.user(value.subject_id),
                "project": service.auth.identities.project(value.project_id)}

    def visible(node: dict, value: Principal) -> dict:
        result = service.view(node)
        if not value.permits("resources:read", node["id"]):
            result["resources"] = None
        return result

    @app.get("/api/v1/health")
    async def health():
        poller = getattr(app.state, "poller", None)
        job_poller = getattr(app.state, "job_poller", None)
        pollers = (poller, job_poller, getattr(app.state, "file_poller", None),
                   getattr(app.state, "transfer_poller", None), getattr(app.state, "agent_poller", None))
        failed = service.poll_error or service.jobs.failed or service.agents.poll_error or (not settings.demo and any(
            task is not None and task.done() for task in pollers))
        return {"status": "degraded" if failed else "ok", "version": __version__}

    @app.post("/api/v1/session")
    async def login(body: Bootstrap, request: Request):
        if request.headers.get("origin") not in origins:
            raise Failure("invalid_origin", "Sign in from the local console.", 403)
        initial = service.auth.resolve(body.bootstrap, ("bootstrap",), consume=True)
        credential, value = service.auth.issue("session", label=initial.label, lifetime=28800,
                                              scopes=initial.scopes, node_ids=initial.node_ids, root_ids=initial.root_ids,
                                              subject_id=initial.subject_id, project_id=initial.project_id)
        response = JSONResponse(session(value))
        session_cookie(response, cookie, credential, value.expires_at, settings.remote is not None)
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
        response.delete_cookie(cookie, path="/", secure=settings.remote is not None, httponly=True, samesite="strict")
        return response

    @app.get("/api/v1/nodes")
    async def nodes(request: Request):
        with service.store.lock:
            value = principal(request, "nodes:read")
            return {"nodes": [visible(node, value) for node in service.store.nodes()
                              if value.permits("nodes:read", node["id"])]}

    @app.get("/api/v1/nodes/{node_id}")
    async def node(node_id: str, request: Request):
        with service.store.lock:
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
        async with service.configuration(node_id):
            service.authorize(value.id, "nodes:write", node_id)
            if editor_retained(service.store, node_id=node_id):
                raise Failure("editor_retained", "Recover and remove retained edit copies before forgetting this machine.", 409)
            if (service.jobs.store.active(node_id) or service.terminals.busy(node_id)
                    or any(root["node_id"] == node_id for root in service.files.registered())
                    or service.files.active(node_id=node_id) or service.transfers.active(node_id=node_id)):
                raise Failure("node_busy", "Remove registered roots and resolve active work before forgetting this machine.", 409)
            if service.retained_history(node_id):
                raise Failure("history_retained", "Archive completed history before forgetting this machine.", 409)
            if any(item["node_id"] == node_id for item in service.containers.records.profiles()) or any(
                    item["node_id"] == node_id for value in service.containers.records.all() for item in value["targets"]):
                raise Failure("container_retained", "Remove container receipts and profiles before forgetting this machine.", 409)
            if any(item["node_id"] == node_id for item in service.administration.records.profiles()) or any(
                    item["node_id"] == node_id for value in service.administration.records.all() for item in value["targets"]):
                raise Failure("admin_retained", "Remove administration profiles and operation receipts before removing this machine.", 409)
            if service.vm_providers.retained(node_id):
                raise Failure("vm_retained", "Remove VM profiles and operation receipts before forgetting this machine.", 409)
            service.store.delete_node(node_id)
            service.ssh.reset(node_id)
            service.store.audit("node.forget", node_id, actor=value.id)
        if node_id in service.locks and not service.locks[node_id].locked():
            service.locks.pop(node_id)
        return {"ok": True}

    @app.get("/api/v1/permissions")
    async def permissions(request: Request):
        value = principal(request)
        return {"scopes": value.scopes, "node_ids": value.effective("nodes"), "root_ids": value.effective("roots")}

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

    install_identity_routes(app, service, principal, session, cookie)
    from .contributor_routes import install as install_contributor_routes
    install_contributor_routes(app, service, principal)
    from .workloads.routes import install as install_workload_routes
    install_workload_routes(app, service, principal)
    install_remote_routes(app, service, principal, cookie)
    install_policy_routes(app, service, principal)
    install_agent_routes(app, service, principal)
    install_file_routes(app, service, principal)
    install_transfer_routes(app, service, principal)
    install_dataset_routes(app, service, principal)
    install_inspection_routes(app, service, principal)
    install_source_routes(app, service, principal)
    install_operation_routes(app, service, principal)
    install_job_routes(app, service, principal)
    install_terminal_routes(app, service, principal, origins, hosts)
    install_workspace_routes(app, service, principal)
    from .workspace_templates import install as install_workspace_templates
    install_workspace_templates(app, service, principal)
    from .workloads.templates import install as install_workload_templates
    install_workload_templates(app, service, principal)
    install_module_routes(app, service, principal)
    install_module_editor(app, service, principal)
    install_module_vms(app, service, principal)
    install_adapter_profiles(app, service, principal)
    install_windows_endpoints(app, service, principal)
    install_module_containers(app, service, principal)
    install_module_administration(app, service, principal)
    install_viewers(app, service, principal, origins, hosts)

    static = Path(__file__).parent / "static"
    if static.is_dir():
        app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    async def index():
        if not (static / "index.html").is_file():
            raise Failure("assets_missing", "The console assets are not installed.", 503)
        return FileResponse(static / "index.html")

    return app
