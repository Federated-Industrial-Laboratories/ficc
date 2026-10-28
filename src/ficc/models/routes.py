# SPDX-License-Identifier: Apache-2.0
"""Project model manifests, bounded upload and asynchronous acquisition."""
import base64
import binascii

from fastapi import Query, Request

from ..errors import Failure
from .hub import Selection, inspect
from .schema import Manifest, Upload


def install(app, service, principal):
    models = service.models
    hub_requests = 0

    @app.post("/api/v1/models/hub-preview")
    async def hub_preview(body: Selection, request: Request):
        nonlocal hub_requests
        actor = principal(request, "models:manage")
        if hub_requests >= 2:
            raise Failure("capacity", "Wait for a model repository lookup to finish.", 429)
        hub_requests += 1
        try:
            hosts = service.store.get_setting("models.https_hosts", ["huggingface.co"])
            result = await inspect(body, hosts)
            models.current(actor, "models:manage")
            return result
        finally:
            hub_requests -= 1

    @app.get("/api/v1/models")
    async def all_models(request: Request):
        actor = principal(request, "models:read")
        return {"models": [models.view(value) for value in models.records.all(actor.project_id)]}

    @app.post("/api/v1/models", status_code=201)
    async def create(body: Manifest, request: Request):
        return models.create(body, principal(request, "models:manage"))

    @app.get("/api/v1/models/{identity}")
    async def get(identity: str, request: Request):
        return models.view(models.get(identity, principal(request, "models:read")))

    @app.post("/api/v1/models/{identity}/acquire", status_code=202)
    async def acquire(identity: str, request: Request):
        from .sources import start
        return start(models, identity, principal(request, "models:manage"))

    @app.post("/api/v1/models/{identity}/pause")
    async def pause(identity: str, request: Request):
        from .sources import pause as pause_download
        return await pause_download(models, identity, principal(request, "models:manage"))

    @app.post("/api/v1/models/{identity}/files/{index}")
    async def upload(identity: str, index: int, body: Upload, request: Request):
        actor = principal(request, "models:manage")
        value = models.get(identity, actor, "models:manage")
        files = Manifest.model_validate(value["manifest"]).files
        if not 0 <= index < len(files):
            raise Failure("not_found", "The model file was not found.", 404)
        try:
            data = base64.b64decode(body.data, validate=True)
        except (ValueError, binascii.Error):
            raise Failure("model_encoding", "Use canonical base64 model bytes.", 422) from None
        if base64.b64encode(data).decode() != body.data:
            raise Failure("model_encoding", "Use canonical base64 model bytes.", 422)
        return await models.cache_for(value).write_async(files[index], body.offset, data)

    @app.post("/api/v1/models/{identity}/files/{index}/bytes")
    async def upload_bytes(identity: str, index: int, request: Request, offset: int = Query(ge=0)):
        actor = principal(request, "models:manage")
        value = models.get(identity, actor, "models:manage")
        files = Manifest.model_validate(value["manifest"]).files
        if not 0 <= index < len(files):
            raise Failure("not_found", "The model file was not found.", 404)
        if request.headers.get("content-type") != "application/octet-stream":
            raise Failure("model_encoding", "Send model bytes as application/octet-stream.", 415)
        data = await request.body()
        models.get(identity, actor, "models:manage")
        return await models.cache_for(value).write_async(files[index], offset, data)

    @app.delete("/api/v1/models/{identity}")
    async def remove(identity: str, request: Request, evict: bool = False):
        return models.remove(identity, principal(request, "models:manage"), evict=evict)
