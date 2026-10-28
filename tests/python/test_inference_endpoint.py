# SPDX-License-Identifier: Apache-2.0
"""Exercise real Unix HTTP streaming, backpressure, cancellation and peer fencing."""
import base64
import http.server
import os
import socketserver
import threading
import time
from pathlib import Path

import pytest

from ficc.execution.endpoints import Connection, Stream
from ficc.execution.ledger import Conflict
from ficc.execution.protocol import EndpointCall


class UnixHTTP(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        try:
            for _ in range(512):
                self.wfile.write(b"x" * 65536)
        except (BrokenPipeError, ConnectionResetError):
            self.server.disconnected.set()


def test_owned_endpoint_stream_has_bounded_queue_and_cancels(tmp_path):
    root = tmp_path / "runtime/work"
    root.mkdir(parents=True)
    path = root / "inference.sock"
    server = UnixHTTP(str(path), Handler)
    server.disconnected = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    group = next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::"))
    ctx = {"directory": str(tmp_path), "slot": {"uid": os.getuid()}, "cgroup": str(Path(group).parent),
           "plan": {"job": {"endpoint": {"socket": "inference.sock"}}}}
    asked = EndpointCall(attempt_id="a" * 32, generation=1, plan_digest="sha256:" + "b" * 64,
                         stream_id="c" * 32, operation="open", path="/health", deadline_seconds=5)
    stream = Stream(asked, ctx, lambda: None)
    try:
        deadline = time.monotonic() + 3
        while not stream.queue.full() and not stream.done and time.monotonic() < deadline:
            time.sleep(0.01)
        assert stream.queue.qsize() == 4
        value = stream.read()
        assert value["status"] == 200 and 0 < len(base64.b64decode(value["data"])) <= 65536
        denied = Connection(path, {**ctx, "cgroup": "/not-this-attempt"}, 1)
        with pytest.raises(Conflict, match="identity"):
            denied.connect()
        stream.cancel()
        stream.thread.join(timeout=2)
        assert not stream.thread.is_alive()
        assert server.disconnected.wait(2)
    finally:
        stream.cancel()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_response_closed_before_first_byte_releases_admission():
    import asyncio

    from ficc.inference.stream import Stream

    released = []
    async def body():
        yield b"unused"
    async def close():
        released.append(True)
    async def check():
        response = Stream(body(), close)
        await response.aclose()
        await response.aclose()
        assert released == [True]
        with pytest.raises(StopAsyncIteration):
            await anext(response)
    asyncio.run(check())


def test_quick_cancel_retry_reaps_only_confirmed_dead_streams(tmp_path):
    from types import SimpleNamespace

    from ficc.execution.endpoints import Endpoints
    root = tmp_path / "runtime/work"
    root.mkdir(parents=True)
    server = UnixHTTP(str(root / "inference.sock"), Handler)
    server.disconnected = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    group = next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::"))
    ctx = {"directory": str(tmp_path), "slot": {"uid": os.getuid()}, "cgroup": str(Path(group).parent),
           "plan": {"job": {"endpoint": {"socket": "inference.sock", "paths": ["/health"], "concurrency": 1}, "inputs": []}}}
    endpoints = Endpoints(SimpleNamespace(check=lambda asked: {"state": "running", "plan": ctx["plan"]}, ctx=lambda value: ctx))
    try:
        for index in range(3):
            asked = EndpointCall(attempt_id="a" * 32, generation=1, plan_digest="sha256:" + "b" * 64,
                                 stream_id=f"{index:032x}", operation="open", path="/health", deadline_seconds=5)
            endpoints.exchange(asked)
            stream = endpoints.streams[(asked.attempt_id, asked.stream_id)]
            limit = time.monotonic() + 2
            while not stream.queue.full() and not stream.done and time.monotonic() < limit:
                time.sleep(0.01)
            assert stream.queue.full()
            endpoints.exchange(asked.model_copy(update={"operation": "cancel"}))
            stream.thread.join(timeout=2)
            assert not stream.thread.is_alive() and time.monotonic() - stream.last_read < 15
        # A completed, uncancelled response still owns its unread bytes.
        stream.cancelled.clear()
        stream.done = True
        with pytest.raises(Conflict, match="capacity"):
            endpoints.exchange(asked.model_copy(update={"stream_id": "f" * 32}))
        stream.cancelled.set()
        endpoints.exchange(asked.model_copy(update={"stream_id": "f" * 32}))
    finally:
        endpoints.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["prefill", "aggregation"])
async def test_real_http_disconnect_cancels_pending_local_inference(phase):
    import asyncio
    import json
    import socket
    from types import SimpleNamespace

    import uvicorn
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    from ficc.errors import Failure
    from ficc.inference.routes import install
    from ficc.inference.stream import Stream as OwnedStream
    entered, closed = asyncio.Event(), asyncio.Event()
    async def cleanup():
        closed.set()
    async def chunks():
        entered.set()
        await asyncio.Future()
        yield b"unused"
    async def invoke(*args):
        if phase == "prefill":
            entered.set()
            try:
                await asyncio.Future()
            finally:
                closed.set()
        return 200, OwnedStream(chunks(), cleanup)
    app = FastAPI()
    @app.exception_handler(Failure)
    async def refused(request, error):
        return JSONResponse({"error": "cancelled"}, status_code=499)
    install(app, SimpleNamespace(inference=SimpleNamespace(gateway=SimpleNamespace(invoke=invoke))), lambda *args: None)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="off", timeout_graceful_shutdown=1))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    writer = None
    try:
        async with asyncio.timeout(3):
            while not server.started:
                await asyncio.sleep(0.01)
        _, writer = await asyncio.open_connection(*sock.getsockname())
        data = json.dumps({"messages": [], "stream": phase == "prefill"}).encode()
        writer.write(b"POST /api/v1/inference/fixture/v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
        await writer.drain()
        await asyncio.wait_for(entered.wait(), 2)
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(closed.wait(), 1)
    finally:
        if writer:
            writer.close()
        server.should_exit = True
        await asyncio.wait_for(task, 3)
        sock.close()


@pytest.mark.asyncio
async def test_cancelled_initial_response_closes_stream_acquired_during_race():
    import asyncio
    from types import SimpleNamespace

    from ficc.errors import Failure
    from ficc.inference.routes import connected
    closed = []
    async def close():
        closed.append(True)
    async def operation():
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            return 200, SimpleNamespace(aclose=close)
    async def disconnected():
        return True
    with pytest.raises(Failure, match="disconnected"):
        await connected(SimpleNamespace(is_disconnected=disconnected), operation())
    assert closed == [True]


@pytest.mark.asyncio
async def test_streaming_response_owns_cleanup_before_body_iteration():
    import asyncio
    from types import SimpleNamespace

    from ficc.inference.routes import OwnedResponse
    closed = []
    async def close():
        closed.append(True)
    async def send(message):
        raise asyncio.CancelledError
    async def receive():
        await asyncio.Future()
    response = OwnedResponse(SimpleNamespace(aclose=close))
    with pytest.raises(asyncio.CancelledError):
        await response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send)
    assert closed == [True]
