# SPDX-License-Identifier: Apache-2.0
"""Expose failed observation and recover whole agent batches after storage errors."""

import asyncio
import sqlite3

import httpx
import pytest

from ficc.api import create_app
from ficc.settings import Settings


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("boundary", ["deliveries", "agents", "exchange"])
async def test_agent_poll_recovers_and_health_reports_storage_failure(tmp_path, monkeypatch, count, boundary):
    app = create_app(Settings(state_dir=tmp_path / "state", control=False))
    manager = app.state.service.agents
    values = [{"id": str(i), "state": "ready"} for i in range(count)]
    failed, recovered = asyncio.Event(), asyncio.Event()
    seen = set()

    def inject(where):
        if where == boundary and not failed.is_set():
            failed.set()
            raise sqlite3.OperationalError("synthetic temporary storage failure")

    def deliveries():
        inject("deliveries")
        return []

    def agents():
        inject("agents")
        return values

    async def exchange(value):
        inject("exchange")
        seen.add(value["id"])
        if len(seen) == count:
            recovered.set()

    monkeypatch.setattr(app.state.service.bus, "deliveries", deliveries)
    monkeypatch.setattr(manager, "all", agents)
    monkeypatch.setattr(manager.store, "get", lambda table, identity: values[int(identity)])
    monkeypatch.setattr(manager, "exchange", exchange)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://127.0.0.1:8170") as client:
            await asyncio.wait_for(failed.wait(), 2)
            async with asyncio.timeout(1):
                while (await client.get("/api/v1/health")).json()["status"] != "degraded":
                    await asyncio.sleep(0.01)
            assert not app.state.agent_poller.done()
            await asyncio.wait_for(recovered.wait(), 3)
            async with asyncio.timeout(1):
                while (await client.get("/api/v1/health")).json()["status"] != "ok":
                    await asyncio.sleep(0.01)
            assert seen == {str(i) for i in range(count)}
            assert not app.state.agent_poller.done()


async def test_health_reports_stopped_agent_task(tmp_path):
    app = create_app(Settings(state_dir=tmp_path / "state", control=False))
    async with app.router.lifespan_context(app):
        app.state.agent_poller.cancel()
        await asyncio.gather(app.state.agent_poller, return_exceptions=True)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://127.0.0.1:8170") as client:
            assert (await client.get("/api/v1/health")).json()["status"] == "degraded"
