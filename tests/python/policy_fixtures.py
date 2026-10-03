# SPDX-License-Identifier: Apache-2.0
"""Build real signed policy packages and configure isolated evaluator workflows."""

import asyncio
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ficc.api import create_app
from ficc.jobs import Jobs
from ficc.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
OPA_SHA256 = "668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"


def signed_pack(destination, key, *, preset="managed", package_id=None, code=None, extra=None, publisher="example-publisher"):
    destination.mkdir()
    source = destination / "source"
    shutil.copytree(ROOT / "policy-packs" / preset, source)
    value = json.loads((source / "package.json").read_text())
    if package_id:
        value["id"] = package_id
    (source / "package.json").write_text(json.dumps(value))
    if code is not None:
        (source / "payload/policy.rego").write_text(code)
    if extra is not None:
        (source / "payload/extra.json").write_text(json.dumps(extra))
    spec = importlib.util.spec_from_file_location("ficc_policy_builder", ROOT / "tools/pack-policy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = destination / "policy.zip"
    module.build(source, publisher, key, output)
    return output.read_bytes()


@pytest.fixture(scope="session")
def policy_material(tmp_path_factory):
    root = tmp_path_factory.mktemp("policy-signing")
    key = root / "signing-key"
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "policy qualification", "-f", str(key)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    return {"key": key, "public_key": key.with_suffix(".pub").read_text(),
            "managed": signed_pack(root / "managed", key),
            "contribution": signed_pack(root / "contribution", key, preset="contribution")}


def configure_policy(storage_state):
    binary = os.environ.get("FICC_TEST_OPA")
    if not binary:
        pytest.skip("Set FICC_TEST_OPA to the qualified static evaluator for real policy workflows.")
    storage_state.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = storage_state / "policy-provider.json"
    path.write_text(json.dumps({"provider": "opa", "configuration": {"binary": binary, "sha256": OPA_SHA256}}))
    path.chmod(0o600)


@pytest.fixture
def policy_console(storage_state, monkeypatch, policy_material):
    configure_policy(storage_state)
    async def idle(self):
        await asyncio.Event().wait()
    monkeypatch.setattr(Jobs, "poll", idle)
    app = create_app(Settings(state_dir=storage_state, control=False, poll_interval=3600, stale_after=7200))
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        service = app.state.service
        secret, _ = service.auth.issue("bootstrap", lifetime=60)
        response = client.post("/api/v1/session", json={"bootstrap": secret},
                               headers={"Origin": "http://127.0.0.1:8170"})
        assert response.status_code == 200
        client.headers.update({"Origin": "http://127.0.0.1:8170", "X-CSRF-Token": response.json()["csrf"]})
        yield client, service, policy_material


def install_pack(client, material, preset="managed"):
    import base64
    response = client.get("/api/v1/policies")
    assert response.status_code == 200, response.text
    if not response.json()["publishers"]:
        response = client.put("/api/v1/policy-publishers", json={"id": "example-publisher", "public_key": material["public_key"],
                                                                "enabled": True, "revision": 0})
        assert response.status_code == 200, response.text
    response = client.post("/api/v1/policy-packages", json={"archive_base64": base64.b64encode(material[preset]).decode()})
    assert response.status_code == 201, response.text
    return response.json()["digest"]


def activate(client, digest):
    state = client.get("/api/v1/policies").json()["state"]
    response = client.post("/api/v1/policy-activation", json={"digest": digest, "revision": state["revision"]})
    assert response.status_code == 200, response.text
    assert response.json()["revision"] == state["revision"] + 1
    return response.json()
