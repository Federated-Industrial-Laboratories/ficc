# SPDX-License-Identifier: Apache-2.0
"""Forward bounded authenticated inference streams without replaying requests."""
import asyncio
import base64
import json
import secrets
import time

from ..errors import Failure
from ..execution.protocol import EndpointCall, EndpointExchange
from ..execution.wire import BatchReply, EndpointResult, Refused
from ..workloads.commands import fence
from .stream import Stream


class Gateway:
    def __init__(self, manager):
        self.manager = manager
        self.active = {}
        self.cursor = {}
        self.loads = {}

    async def exchange(self, attempt, stream, operation, path, body, check, deadline, input_object=None):
        queue = self.manager.service.workloads
        check()
        call = EndpointCall(**fence(attempt), stream_id=stream, operation=operation, path=path,
                            method="POST" if body is not None or input_object is not None else "GET", body=json.dumps(body) if body is not None else "",
                            deadline_seconds=deadline, input_object=input_object)
        async with queue.runner.lock(attempt.node_id):
            reply = await queue.channel.request(attempt.node_id, EndpointExchange(version=1, id=secrets.token_hex(16), action="endpoint", calls=[call]), check)
        if not isinstance(reply, BatchReply) or len(reply.results) != 1:
            raise Failure("endpoint_protocol", "The executor did not return one endpoint response.", 502)
        value = reply.results[0]
        if isinstance(value, Refused):
            raise Failure(value.error.code, value.error.message, 409)
        if not isinstance(value, EndpointResult) or value.stream_id != stream or value.model_dump(include=set(fence(attempt))) != fence(attempt):
            raise Failure("endpoint_protocol", "The response does not bind this inference stream.", 502)
        return value

    async def response(self, attempt, path, body, check, deadline=120, input_object=None):
        stream = secrets.token_hex(16)
        end = time.monotonic() + deadline
        opened = False
        async def call(operation):
            if operation != "cancel" and time.monotonic() >= end:
                raise Failure("inference_deadline", "The inference deadline was reached.", 504)
            return await self.exchange(attempt, stream, operation, path, body, check, deadline, input_object)
        async def cancel():
            nonlocal opened
            if opened:
                opened = False
                try:
                    await self.exchange(attempt, stream, "cancel", path, None, lambda: None, deadline, input_object)
                except (Failure, OSError, TimeoutError):
                    pass
        try:
            opened = True
            value = await call("open")
            while not value.status and not value.eof:
                await asyncio.sleep(0.03)
                value = await call("read")
            if not value.status:
                raise Failure("endpoint_unavailable", "The engine endpoint is not available yet.", 503)
        except BaseException:
            await cancel()
            raise
        async def chunks():
            current = value
            try:
                while True:
                    check()
                    if current.data:
                        yield base64.b64decode(current.data, validate=True)
                    if current.error:
                        raise Failure("endpoint_interrupted", "The engine stream ended unexpectedly; the request was not replayed.", 502)
                    if current.eof:
                        break
                    await asyncio.sleep(0.03)
                    current = await call("read")
            finally:
                await cancel()
        return value.status, Stream(chunks(), cancel)

    async def json(self, attempt, path, body, check, deadline=120, input_object=None):
        status, chunks = await self.response(attempt, path, body, check, deadline, input_object)
        data = bytearray()
        try:
            async for chunk in chunks:
                data.extend(chunk)
                if len(data) > 2 * 1024 * 1024:
                    raise Failure("endpoint_limit", "The engine response exceeds the bounded JSON limit.", 502)
        finally:
            await chunks.aclose()
        if not 200 <= status < 300:
            raise Failure("engine_refused", "The engine rejected this request; inspect the service runtime logs.", 502)
        if not data and (path == "/health" or path.startswith("/api/blobs/")):
            return {}
        try:
            return json.loads(data)
        except (ValueError, UnicodeDecodeError):
            raise Failure("engine_protocol", "The engine returned an invalid JSON response.", 502) from None

    async def invoke(self, identity, path, body, actor):
        manager = self.manager
        record = manager.get(identity, actor, "inference:invoke")
        if record["desired"] != "running" or record["state"] not in {"ready", "degraded"}:
            raise Failure("service_not_ready", "This inference service is not ready to receive requests.", 409)
        if record["spec"]["engine"] == "attached":
            return await manager.attached.invoke(record, path, body, actor)
        capability = "embeddings" if path == "/v1/embeddings" else "chat"
        model = manager.service.models.records.get(record["spec"]["model_id"])
        if path not in {"/v1/chat/completions", "/v1/embeddings"} or capability not in model["manifest"]["capabilities"]:
            raise Failure("inference_capability", "The selected model does not offer this operation.", 409)
        body = dict(body)
        body["model"] = record["spec"]["alias"]
        if len(json.dumps(body).encode()) > 512 * 1024:
            raise Failure("inference_limit", "The inference request exceeds 512 KiB.", 413)
        attempts = [item for item in manager.ready_attempts(record) if self.loads.get(item.id, 0) < record["spec"]["concurrency"]]
        count = self.active.get(identity, 0)
        if not attempts or count >= len(record["workloads"]) * record["spec"]["concurrency"]:
            raise Failure("inference_capacity", "All ready inference slots are occupied.", 429)
        index = self.cursor.get(identity, 0)
        attempt = attempts[index % len(attempts)]
        self.cursor[identity] = index + 1
        self.active[identity] = count + 1
        self.loads[attempt.id] = self.loads.get(attempt.id, 0) + 1
        def check():
            current = manager.get(identity, actor, "inference:invoke")
            if current["generation"] != record["generation"] or current["desired"] == "stopped":
                raise Failure("service_changed", "The inference service generation changed.", 409)
            manager.service.workloads.runner.authority(attempt)
        try:
            status, chunks = await self.response(attempt, path, body, check, record["spec"]["deadline_seconds"])
        except BaseException:
            self.active[identity] -= 1
            self.loads[attempt.id] -= 1
            raise
        async def finish():
            try:
                await chunks.aclose()
            finally:
                self.active[identity] -= 1
                self.loads[attempt.id] -= 1
        return status, Stream(chunks, finish)
