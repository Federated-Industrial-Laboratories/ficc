# SPDX-License-Identifier: Apache-2.0
"""Detect revoked queued dispatch and recoverable observation failures."""

import asyncio
import sqlite3
import time

import httpx
import pytest
from conftest import node, sample

from ficc.api import create_app
from ficc.errors import Failure
from ficc.settings import Settings


@pytest.mark.parametrize("boundary", ["enrollment", "connections"])
@pytest.mark.parametrize("change", ["revoke", "expire", "scope", "node"])
async def test_queued_enrollment_rechecks_current_authority(tmp_path, monkeypatch, boundary, change):
    app = create_app(Settings(state_dir=tmp_path / "state", control=False))
    service = app.state.service
    token, actor = service.auth.issue("token")
    preview_id = "a" * 32
    service.previews[preview_id] = {**node(), "actor": actor.id, "trust": "trusted",
                                   "helper_install_required": True, "expires_at": time.time() + 120}
    admitted = asyncio.Event()
    original = service.auth.resolve

    def resolve(*args, **kwargs):
        value = original(*args, **kwargs)
        admitted.set()
        return value

    installs = []

    async def install(value, check=None):
        installs.append(value["id"])

    async def probe(value, check=None):
        return sample()

    monkeypatch.setattr(service.auth, "resolve", resolve)
    monkeypatch.setattr(service.ssh, "install", install)
    monkeypatch.setattr(service.ssh, "probe", probe)
    gate = service.enrollment if boundary == "enrollment" else service.connections
    slots = 1 if boundary == "enrollment" else 4
    for _ in range(slots):
        await gate.acquire()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://127.0.0.1:8170") as client:
            pending = asyncio.create_task(client.post("/api/v1/nodes", headers={
                "Authorization": "Bearer " + token}, json={"preview_id": preview_id,
                "expected_fingerprint": "SHA256:synthetic-key", "install_helper": True}))
            await asyncio.wait_for(admitted.wait(), 2)
            assert not pending.done()
            if change == "revoke":
                service.auth.revoke(actor.id)
            else:
                field, value = {"expire": ("expires", 0), "scope": ("scopes", '["nodes:read"]'),
                                "node": ("nodes", "[]")}[change]
                with service.store.db:
                    service.store.db.execute(f"UPDATE credentials SET {field}=? WHERE id=?", (value, actor.id))
            for _ in range(slots):
                gate.release()
            result = await asyncio.wait_for(pending, 2)
            assert result.status_code == (401 if change in {"revoke", "expire"} else 403)
            assert installs == [] and service.store.nodes() == []
    finally:
        service.store.close()


async def test_authority_rechecked_after_ssh_configuration_wait(tmp_path, monkeypatch):
    import ficc.ssh as ssh_module
    app = create_app(Settings(state_dir=tmp_path / "state", control=False))
    service = app.state.service
    _, actor = service.auth.issue("token")
    entered, release = asyncio.Event(), asyncio.Event()
    commands = []

    async def config(profile):
        entered.set()
        await release.wait()
        return {"hostname": "machine-0.example", "user": "operator", "port": 22}

    async def run(command, payload):
        commands.append(command)
        return 0, b"", b""

    monkeypatch.setattr(service.ssh, "config", config)
    monkeypatch.setattr(ssh_module, "run", run)
    pending = asyncio.create_task(service.ssh.install(
        node(), check=lambda: service.authorize(actor.id, "nodes:write")))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        service.auth.revoke(actor.id)
        release.set()
        with pytest.raises(Failure) as denied:
            await pending
        assert denied.value.code == "unauthenticated" and commands == []
    finally:
        service.store.close()


async def test_poller_recovers_after_transient_storage_failure(tmp_path, monkeypatch):
    app = create_app(Settings(state_dir=tmp_path / "state", control=False,
                              poll_interval=1, stale_after=2))
    service = app.state.service
    service.store.save_node(node())
    failed, recovered = asyncio.Event(), asyncio.Event()
    original = service.store.save_node
    saves = 0

    async def probe(value, check=None):
        return sample()

    def save(value):
        nonlocal saves
        saves += 1
        if saves == 1:
            failed.set()
            raise sqlite3.OperationalError("database or disk is full")
        original(value)
        recovered.set()

    monkeypatch.setattr(service.ssh, "probe", probe)
    monkeypatch.setattr(service.store, "save_node", save)
    task = asyncio.create_task(service.poll())
    app.state.poller = task
    try:
        await asyncio.wait_for(failed.wait(), 2)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://127.0.0.1:8170") as client:
            async with asyncio.timeout(2):
                while (await client.get("/api/v1/health")).json()["status"] != "degraded":
                    await asyncio.sleep(0.01)
            await asyncio.wait_for(recovered.wait(), 3)
            async with asyncio.timeout(2):
                while (await client.get("/api/v1/health")).json()["status"] != "ok":
                    await asyncio.sleep(0.01)
        assert not task.done() and saves >= 2
        assert service.view(service.store.node("node-0"))["stale"] is False
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        service.store.close()


async def test_revoked_refresh_does_not_replace_node_state(tmp_path, monkeypatch):
    app = create_app(Settings(state_dir=tmp_path / "state", control=False))
    service = app.state.service
    initial = node()
    service.store.save_node(initial)
    _, actor = service.auth.issue("token")

    async def probe(value, check=None):
        service.auth.revoke(actor.id)
        check()
        return sample()

    monkeypatch.setattr(service.ssh, "probe", probe)
    try:
        with pytest.raises(Failure) as denied:
            await service.refresh([initial["id"]], actor=actor.id)
        assert denied.value.code == "unauthenticated"
        assert service.store.node(initial["id"]) == initial
    finally:
        service.store.close()
