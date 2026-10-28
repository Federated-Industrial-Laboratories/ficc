# SPDX-License-Identifier: Apache-2.0
"""Exercise a real HTTP stream through approved attachment, revocation and lifecycle controls."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ficc.errors import Failure
from ficc.inference.attached import Attached, Attachment, Profile


@pytest.mark.parametrize("operation", ["create", "replace"])
def test_attachment_rechecks_authority_after_audit_wait(console, monkeypatch, operation):
    client, service = console
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    profile = Profile(name="existing", projects=[actor.project_id], url="http://127.0.0.1:1/v1",
                      model="external-model", capabilities=["chat"])
    service.store.set_setting("inference.endpoint_profiles", [profile.model_dump()])
    manager = service.inference
    manager.attached = Attached(manager)
    selected = manager.attached.available(actor)[0]
    spec = Attachment(alias="approved", engine="attached", profile=selected["name"], profile_digest=selected["digest"])
    async def check():
        previous = None
        if operation == "replace":
            previous = await manager.create(spec, actor)
            previous.update(state="stopped", desired="stopped")
            manager.records.save(previous)
        async def revoke_during_audit(*_args):
            await asyncio.sleep(0)
            service.auth.revoke(actor.id)
        monkeypatch.setattr(service.audit_delivery, "require", revoke_during_audit)
        with pytest.raises(Failure):
            if previous is None:
                await manager.create(spec, actor)
            else:
                await manager.replace(previous["id"], spec, previous["revision"], actor)
        records = manager.records.all(actor.project_id)
        assert len(records) == (1 if previous else 0)
        if previous:
            assert records[0]["state"] == "stopped" and records[0]["generation"] == 1
    asyncio.run(check())


def test_attached_real_http_stream_respects_grants_cancel_and_stop(console):
    client, service = console
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    closed = threading.Event()
    received = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            assert self.path == "/v1/models"
            raw = json.dumps({"data": [{"id": "external-model"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            try:
                while not closed.wait(0.01):
                    self.wfile.write(b'data: {"choices":[{"delta":{"content":"token"}}]}\n\n')
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                closed.set()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    profile = Profile(name="existing", projects=[actor.project_id], url=f"http://127.0.0.1:{server.server_port}/v1",
                      model="external-model", capabilities=["chat"])
    service.store.set_setting("inference.endpoint_profiles", [profile.model_dump()])
    service.inference.attached = Attached(service.inference)
    selected = service.inference.attached.available(actor)[0]
    spec = Attachment(alias="approved", engine="attached", profile=selected["name"], profile_digest=selected["digest"])
    async def lifecycle():
        manager = service.inference
        value = await manager.create(spec, actor)
        await manager.attached.health(value)
        value = manager.records.get(value["id"])
        value["state"] = "ready"
        manager.records.save(value)
        scoped = service.auth.resolve(manager.token(value["id"], actor)["token"])
        status, chunks = await manager.gateway.invoke(value["id"], "/v1/chat/completions", {"stream": True, "messages": []}, scoped)
        assert status == 200
        assert b"data:" in await asyncio.wait_for(anext(chunks), 2)
        with pytest.raises(Failure, match="occupied"):
            await manager.gateway.invoke(value["id"], "/v1/chat/completions", {}, actor)
        service.auth.revoke(scoped.id)
        with pytest.raises(Failure):
            await anext(chunks)
        await chunks.aclose()
        assert manager.gateway.active[value["id"]] == 0
        current = manager.records.get(value["id"])
        await manager.control(value["id"], "stop", current["revision"], actor)
        current = manager.records.get(value["id"])
        await manager.reconcile(current)
        assert manager.get(value["id"], actor)["state"] == "stopped"
        assert received[0]["model"] == "external-model"
    try:
        asyncio.run(lifecycle())
        assert closed.wait(2)
        with pytest.raises(ValueError, match="loopback"):
            Profile(**{**profile.model_dump(), "url": "http://192.0.2.1/v1"})
    finally:
        closed.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
