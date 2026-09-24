# SPDX-License-Identifier: Apache-2.0
"""Verify distinct batches, stale data, and enrollment transitions."""

import asyncio
import time

import pytest
from conftest import node, sample

from ficc.errors import Failure
from ficc.schema import Sample


@pytest.mark.parametrize("count", [1, 64])
def test_distinct_batch_observations_are_bounded(console, monkeypatch, count):
    client, service = console
    active = maximum = 0
    seen = []

    async def probe(value, check=None):
        nonlocal active, maximum
        active += 1
        maximum = max(active, maximum)
        index = int(value["id"].split("-")[1])
        seen.append(index)
        await asyncio.sleep(0.002)
        active -= 1
        return sample(index)

    monkeypatch.setattr(service.ssh, "probe", probe)
    for index in range(count):
        service.store.save_node(node(index))
    response = client.post("/api/v1/nodes/refresh", json={"node_ids": [f"node-{i}" for i in range(count)]})
    assert response.status_code == 200
    values = response.json()["nodes"]
    assert len(values) == count and len(set(seen)) == count
    assert maximum <= 16
    for index, value in enumerate(values):
        assert value["id"] == f"node-{index}"
        assert value["resources"]["cpu_count"] == index + 1
        assert value["state"] == "ready" and value["stale"] is False
        assert "key" not in value and "port" not in value


def test_partial_failure_retains_sample_and_age(console, monkeypatch):
    client, service = console
    value = node()
    value.update(resources=sample()["resources"], last_seen=time.time() - 8000, state="ready")
    service.store.save_node(value)

    async def unavailable(value, check=None):
        raise Failure("unreachable", "The connection timed out.", 502)

    monkeypatch.setattr(service.ssh, "probe", unavailable)
    before = client.get("/api/v1/nodes/node-0").json()
    assert before["state"] == "degraded" and before["stale"] is True
    result = client.post("/api/v1/nodes/refresh", json={"node_ids": ["node-0"]}).json()["nodes"][0]
    assert result["state"] == "unreachable" and result["stale"] is True
    assert result["resources"] == sample()["resources"]
    assert result["last_seen"] == value["last_seen"]


def test_unknown_sample_remains_unknown(console):
    client, service = console
    service.store.save_node(node())
    value = client.get("/api/v1/nodes/node-0/resources").json()
    assert value == {"node_id": "node-0", "resources": None, "last_seen": None, "stale": True}


def test_enrollment_requires_preview_actor_key_and_install_consent(console, monkeypatch):
    client, service = console
    installs = []

    async def preview(profile, name, check=None):
        return {**node(), "profile": profile, "name": name, "trust": "trusted", "helper_version": None,
                "helper_install_required": True, "warnings": [], "expires_at": time.time() + 60}

    async def install(value, check=None):
        installs.append(value["profile"])

    async def probe(value, check=None):
        return sample()

    monkeypatch.setattr(service.ssh, "preview", preview)
    monkeypatch.setattr(service.ssh, "install", install)
    monkeypatch.setattr(service.ssh, "probe", probe)
    result = client.post("/api/v1/node-previews", json={"profile": "lab", "name": "Machine"})
    assert result.status_code == 200
    body = {"preview_id": result.json()["preview_id"], "expected_fingerprint": "SHA256:wrong-key-value",
            "install_helper": True}
    assert client.post("/api/v1/nodes", json=body).status_code == 409
    body.update(expected_fingerprint="SHA256:synthetic-key", install_helper=False)
    assert client.post("/api/v1/nodes", json=body).status_code == 409
    body["install_helper"] = True
    enrolled = client.post("/api/v1/nodes", json=body)
    assert enrolled.status_code == 200 and enrolled.json()["state"] == "ready"
    assert installs == ["lab"]
    assert client.post("/api/v1/nodes", json=body).status_code == 409


def test_helper_protocol_rejects_out_of_range_and_oversize_metrics():
    value = sample()
    Sample.model_validate(value)
    value["resources"]["cpu_percent"] = 101.0
    with pytest.raises(ValueError):
        Sample.model_validate(value)
    value["resources"]["cpu_percent"] = 0.0
    value["resources"]["network"] = [{"name": "eth0", "rx_bytes": 0, "tx_bytes": 0}] * 65
    with pytest.raises(ValueError):
        Sample.model_validate(value)


def test_batch_rejects_duplicate_targets(console):
    client, service = console
    service.store.save_node(node())
    result = client.post("/api/v1/nodes/refresh", json={"node_ids": ["node-0", "node-0"]})
    assert result.status_code == 400
