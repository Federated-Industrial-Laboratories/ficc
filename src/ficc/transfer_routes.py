# SPDX-License-Identifier: Apache-2.0
"""Expose verified transfer progress and bounded browser file delivery."""

import asyncio
import os
from typing import Annotated
from urllib.parse import quote

from fastapi import Query, Request
from fastapi.responses import StreamingResponse
from ficc_node.file_access import CHUNK, file_hash, opened, regular, root_fd

from .errors import Failure
from .file_schema import Cancel, Confirm, Selection, TransferPreview
from .file_worker import owned


class DownloadResponse(StreamingResponse):
    """Own the spool until the entire ASGI response has finished or disconnected."""

    def __init__(self, fd, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fd = fd

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            os.close(self.fd)


def install(app, service, principal):
    transfers = service.transfers

    @app.post("/api/v1/transfer-previews")
    async def preview(body: TransferPreview, request: Request):
        return await transfers.preview(body.model_dump(), principal(request).id)

    @app.post("/api/v1/transfers", status_code=202)
    async def submit(body: Confirm, request: Request):
        actor = principal(request).id
        result = await transfers.submit(body.preview_id, request.headers.get("idempotency-key", ""), actor)
        return transfers.view(result, actor, mutation_ids=[item["id"] for item in result["items"]])

    @app.get("/api/v1/transfers")
    async def listing(request: Request):
        actor, result = principal(request).id, []
        for operation in transfers.store.iterate():
            try:
                result.append(transfers.view(operation, actor))
            except Failure as exc:
                if exc.status != 404:
                    raise
            if len(result) == 200:
                break
        return {"transfers": result[:200]}

    @app.get("/api/v1/transfers/{operation_id}")
    async def detail(operation_id: str, request: Request):
        return transfers.view(transfers.store.get(operation_id), principal(request).id)

    @app.post("/api/v1/transfers/{operation_id}/resume")
    async def resume(operation_id: str, body: Selection, request: Request):
        return await transfers.change(operation_id, body.item_ids, principal(request).id, resume=True)

    @app.post("/api/v1/transfers/{operation_id}/cancel")
    async def cancel(operation_id: str, body: Cancel, request: Request):
        return await transfers.change(operation_id, body.item_ids, principal(request).id, discard=body.discard_partial)

    @app.put("/api/v1/transfers/{operation_id}/items/{item_id}/chunks")
    async def upload(operation_id: str, item_id: str, request: Request,
                     offset: Annotated[int, Query(ge=0, le=16*1024**3)]):
        if request.headers.get("content-type") != "application/octet-stream":
            raise Failure("invalid_content_type", "Send file chunks as application/octet-stream.", 415)
        data = await request.body()
        if len(data) > CHUNK:
            raise Failure("request_limit", "The file chunk exceeds 256 KiB.", 413)
        return await transfers.upload(operation_id, item_id, principal(request).id, offset, data,
                                      request.headers.get("x-chunk-sha256", ""))

    @app.post("/api/v1/transfers/{operation_id}/items/{item_id}/finish")
    async def finish(operation_id: str, item_id: str, request: Request):
        return await transfers.finish(operation_id, item_id, principal(request).id)

    @app.get("/api/v1/transfers/{operation_id}/items/{item_id}/content")
    async def content(operation_id: str, item_id: str, request: Request):
        actor = principal(request).id
        operation, item = transfers.selected(operation_id, item_id, actor)
        if operation["kind"] != "download" or item["state"] != "succeeded":
            raise Failure("download_unavailable", "Prepare a verified download before receiving it.", 409)

        async def read(function, *args, cancellable=False):
            transport = service.files.transport
            local = transport.endpoints.setdefault("local", asyncio.Semaphore(2))
            async with transport.workers, local:
                transfers.check(actor, item, operation["kind"])
                result = await owned(function, *args, cancellable=cancellable)
                transfers.check(actor, item, operation["kind"])
                return result

        try:
            with root_fd(item["destination"]["root"]) as root:
                fd = opened(root, item["id"].encode(), os.O_RDONLY)
            regular(os.fstat(fd))
            if await read(file_hash, fd, cancellable=True) != item["sha256"]:
                raise Failure("digest_mismatch", "The prepared download failed verification.", 409)
            transfers.check(actor, item, operation["kind"])
        except BaseException:
            if "fd" in locals():
                os.close(fd)
            raise

        async def stream():
            offset = 0
            while offset < item["size"]:
                transfers.check(actor, item, operation["kind"])
                data = await read(os.pread, fd, min(CHUNK, item["size"]-offset), offset)
                if not data:
                    raise Failure("source_changed", "The prepared download changed.", 409)
                offset += len(data)
                yield data

        return DownloadResponse(fd, stream(), media_type="application/octet-stream", headers={
            "Content-Length": str(item["size"]), "X-Content-SHA256": item["sha256"],
            "Content-Disposition": f"attachment; filename=\"ficc-download-{item_id}\"; filename*=UTF-8''{quote(item['name'], safe='')}"})
