# SPDX-License-Identifier: Apache-2.0
"""Provide isolated authenticated API fixtures."""

import pytest
from fastapi.testclient import TestClient

from ficc.api import create_app
from ficc.settings import Settings


@pytest.fixture
def console(tmp_path):
    app = create_app(Settings(state_dir=tmp_path / "state", control=False, poll_interval=3600,
                              stale_after=7200, profiles=("lab",)))
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        credential, _ = app.state.service.auth.issue("bootstrap", lifetime=60)
        response = client.post("/api/v1/session", json={"bootstrap": credential},
                               headers={"Origin": "http://127.0.0.1:8170"})
        assert response.status_code == 200
        client.headers.update({"Origin": "http://127.0.0.1:8170",
                               "X-CSRF-Token": response.json()["csrf"]})
        yield client, app.state.service


def sample(index=0):
    return {"version": "1", "boot_id": "00000000-0000-0000-0000-000000000001",
            "observed_at": 100.0, "monotonic_seconds": 50.0,
            "helper_version": "1", "python_version": "python3.12",
            "capabilities": {"resources": True},
            "resources": {"cpu_percent": float(index), "cpu_count": index + 1,
                          "load": [0.0, 0.0, 0.0], "memory_total_bytes": 100000 + index,
                          "memory_available_bytes": 50000 + index, "uptime_seconds": 100.0,
                          "storage": [], "network": [], "gpus": [], "gpu_status": "unsupported"}}


def node(index=0):
    return {"id": f"node-{index}", "name": f"Machine {index}", "profile": f"lab-{index}",
            "host": f"machine-{index}.example", "account": "operator", "port": 22,
            "fingerprint": "SHA256:synthetic-key", "key_type": "ssh-ed25519", "key": "dGVzdA==",
            "state": "unconfigured", "last_seen": None, "resources": None,
            "capabilities": {}, "error": None}
