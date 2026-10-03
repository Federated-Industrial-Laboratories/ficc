# SPDX-License-Identifier: Apache-2.0
"""Verify module target authority and the packaged status module through the host."""

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import node, sample
from test_modules_packages import bundle, package

from ficc.errors import Failure
from ficc.module_broker import handler
from ficc.module_capabilities import validate_instance
from ficc.modules import inspect_archive
from ficc.workspace_schema import Instance

ROOT = Path(__file__).resolve().parents[2]


def status_archive():
    source = ROOT / "modules/system-status"
    manifest = json.loads((source / "manifest.json").read_text())
    files = {"main.py": (source / "payload/main.py").read_bytes(),
             "ficc_module.py": (ROOT / "sdk/python/ficc_module.py").read_bytes()}
    manifest["files"] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    return bundle(manifest, files)


def systems(service, count):
    values = []
    for index in range(count):
        value = node(index)
        value.update(id=f"{index + 1:032x}", resources=sample(index)["resources"], state="ready")
        service.store.save_node(value)
        values.append(value)
    return values


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_broker_filters_private_fields_and_checks_each_current_target(console, count):
    _, service = console
    values = systems(service, count)
    credential, actor = service.auth.issue("token", scopes=["nodes:read", "resources:read"])
    checked = inspect_archive(bundle(*package(capabilities=["system:read"])))
    service.modules.install(checked, checked.digest)
    service.modules.set_enabled(checked.digest, True, [{"capability": "system:read",
        "target_ids": [value["id"] for value in values]}])
    calls = []
    call = SimpleNamespace(primitive="system.resources.read", action_capabilities=("system:read",),
        target_ids=tuple(value["id"] for value in values), parameters={}, package_digest=checked.digest,
        check=lambda: calls.append(True))
    result = await handler(service, actor.id)(call)
    assert len(result) == count and len(calls) == count * 2 + 1
    for index, item in enumerate(result):
        assert item["target"] == values[index]["id"]
        assert item["data"]["resources"]["cpu_count"] == index + 1
        assert not {"key", "key_type", "profile", "fingerprint", "account", "host"} & item["data"].keys()
    service.auth.revoke(actor.id)
    refused = await handler(service, actor.id)(call)
    assert all(item["error"]["code"] == "unauthenticated" for item in refused)
    call.primitive = "system.command"
    with pytest.raises(Failure, match="primitive"):
        await handler(service, actor.id)(call)


def test_instance_scope_uses_each_capability_target_type(console):
    client, service = console
    system = systems(service, 1)[0]
    space = client.post("/api/v1/workspaces", json={"name": "Systems"}).json()
    checked = inspect_archive(bundle(*package(capabilities=["system:read", "workspace:read"])))
    service.modules.install(checked, checked.digest)
    service.modules.set_enabled(checked.digest, True, [
        {"capability": "workspace:read", "target_ids": [space["id"]]},
        {"capability": "system:read", "target_ids": [system["id"]]},
    ])
    instance = Instance(id="f" * 32, digest=checked.digest, title="System", targets=[system["id"]])
    validate_instance(service, space["id"], instance)
    instance.targets = [space["id"]]
    with pytest.raises(Failure):
        validate_instance(service, space["id"], instance)
    instance.targets = []
    with pytest.raises(Failure, match="Select targets"):
        validate_instance(service, space["id"], instance)
    body = {"workspace_id": space["id"], "instance_id": "f" * 32, "action": "load",
            "targets": [space["id"]], "parameters": {}}
    instance.targets = [system["id"]]
    result = client.put(f"/api/v1/workspaces/{space['id']}", json={"revision": 0,
        "name": "Systems", "instances": [instance.model_dump()]})
    assert result.status_code == 200, result.text
    result = client.post("/api/v1/module-invocations", json=body)
    assert result.status_code == 403 and result.json()["error"]["code"] == "module_target_denied"


@pytest.mark.skipif(os.environ.get("FICC_MODULE_HOST_TESTS") != "1", reason="Requires the actual module sandbox")
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_status_package_installs_grants_and_runs_in_real_sandbox(console, count):
    client, service = console
    values = systems(service, count)
    space = client.post("/api/v1/workspaces", json={"name": "Systems"}).json()
    result = client.post("/api/v1/module-install-previews", content=status_archive())
    assert result.status_code == 200, result.text
    preview = result.json()
    result = client.post("/api/v1/modules", json={"preview_id": preview["preview_id"],
        "digest": preview["digest"], "accept_unverified": True})
    assert result.status_code == 201, result.text
    targets = [value["id"] for value in values]
    result = client.post(f"/api/v1/modules/{preview['digest']}/activation", json={"enabled": True,
        "grants": [{"capability": "workspace:read", "target_ids": [space["id"]]},
                   {"capability": "system:read", "target_ids": targets}]})
    assert result.status_code == 200, result.text
    instance = {"id": "f" * 32, "digest": preview["digest"], "title": "Systems", "state": {}, "targets": targets}
    assert client.put(f"/api/v1/workspaces/{space['id']}", json={"revision": 0,
        "name": "Systems", "instances": [instance]}).status_code == 200
    body = {"workspace_id": space["id"], "instance_id": instance["id"], "action": "load",
            "targets": targets, "parameters": {}}
    result = client.post("/api/v1/module-invocations", json=body)
    assert result.status_code == 200, result.text
    results = result.json()["results"]
    assert [item["target"] for item in results] == targets
    rows = results[0]["data"]["rows"]
    assert len(rows) == count
    assert [row["values"]["cpu"] for row in rows] == list(map(float, range(count)))
    assert all(row["values"]["freshness"] == "Stale" for row in rows)
    service.modules.revoke(preview["digest"])
    refused = client.post("/api/v1/module-invocations", json=body)
    assert refused.status_code == 403 and refused.json()["error"]["code"] == "module_disabled"
