# SPDX-License-Identifier: Apache-2.0
"""Run project resource workflows with real state backends and isolated users."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from ficc.api import create_app
from ficc.jobs import Jobs
from ficc.settings import Settings


@pytest.fixture
def resource_console(storage_state, monkeypatch):
    async def idle(self):
        await asyncio.Event().wait()
    monkeypatch.setattr(Jobs, "poll", idle)
    app = create_app(Settings(state_dir=storage_state, control=False, poll_interval=3600,
                              stale_after=7200, profiles=("lab",)))
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        service = app.state.service
        secret, _ = service.auth.issue("bootstrap", lifetime=60)
        response = client.post("/api/v1/session", json={"bootstrap": secret},
                               headers={"Origin": "http://127.0.0.1:8170"})
        assert response.status_code == 200
        client.headers.update({"Origin": "http://127.0.0.1:8170", "X-CSRF-Token": response.json()["csrf"]})
        yield client, service


def assign(client, project, nodes=(), roots=(), revision=0):
    result = client.put(f"/api/v1/projects/{project['id']}/resources", json={
        "node_ids": list(nodes), "root_ids": list(roots), "revision": revision})
    assert result.status_code == 200, result.text
    return result.json()
