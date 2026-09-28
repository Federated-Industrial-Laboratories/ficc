# SPDX-License-Identifier: Apache-2.0
"""Exercise Proxmox through shared VM routes, grants, backup and retained task history."""

import json
import secrets
import sqlite3

import pytest
from conftest import node
from ficc_node import proxmox_rpc, proxmox_spec
from test_module_proxmox_runtime import node as provider_fixture
from test_module_vm_routes import fixture as libvirt_fixture
from test_modules_packages import bundle, package

from ficc.backup_database import quiescent, sanitize
from ficc.modules import inspect_archive
from ficc.workspace_schema import WorkspaceUpdate

BASE = "/api/v1/module-vms/"
NODE = "0" * 32


def fixture(console, tmp_path, monkeypatch, count):
    client, service = console
    bridge = provider_fixture(tmp_path, monkeypatch, count)
    service.store.save_node({**node(), "id": NODE})
    actor = service.auth.resolve(client.cookies.get("ficc_session")).id

    async def command(node, command, payload, check, timeout):
        check()
        result = proxmox_rpc.dispatch(proxmox_spec.decode(payload))
        check()
        return 0, proxmox_spec.encode({"version": 1, "data": result}), b""
    monkeypatch.setattr(service.ssh, "command", command)
    profile = client.put(f"/api/v1/nodes/{NODE}/proxmox-profile", json={"enabled": True})
    assert profile.status_code == 200, profile.text
    workspace = service.workspaces.create("Proxmox")
    checked = inspect_archive(bundle(*package(capabilities=["workspace:read", "vm:read", "vm:power"], optional_capabilities=["vm:power"])))
    service.modules.install(checked, checked.digest)
    grants = [{"capability": cap, "target_ids": [workspace["id"]] if cap == "workspace:read" else [NODE]}
              for cap in checked.manifest["capabilities"]]
    service.modules.set_enabled(checked.digest, True, grants)
    context = {"workspace_id": workspace["id"], "instance_id": secrets.token_hex(16)}
    item = {"id": context["instance_id"], "digest": checked.digest, "title": "Proxmox", "targets": [NODE]}
    service.workspaces.update(workspace["id"], WorkspaceUpdate(revision=0, name="Proxmox", instances=[item]))
    ids = [service.proxmox.resource_id(profile.json()["id"], uuid) for uuid in bridge.rows]
    preview = client.portal.call(service.proxmox.preview, actor, checked.digest, context["instance_id"],
                                 [NODE], {"action": "start", "vm_ids": ids}, lambda: None)
    return context, preview, bridge, checked.digest, grants


@pytest.mark.parametrize("count", [1, 64])
def test_confirm_task_observation_retention_restore_and_cleanup(console, tmp_path, monkeypatch, count):
    client, service = console
    context, preview, bridge, digest, grants = fixture(console, tmp_path, monkeypatch, count)
    assert len(client.get("/api/v1/proxmox-profiles").json()["profiles"]) == 1
    assert client.get("/api/v1/vm-profiles").json()["profiles"] == []
    body = {**context, "preview_id": preview["preview_id"]}
    assert client.post(BASE + "preview", json=body).json() == preview
    key = secrets.token_hex(16)
    def commit(**headers):
        return client.post(BASE + "commit", json={**body, "confirm": True}, headers={"Idempotency-Key": key, **headers})

    assert commit(**{"X-CSRF-Token": "bad"}).status_code == 403
    result = commit()
    assert result.status_code == 200, result.text
    operation = result.json()
    assert operation["provider"] == "proxmox" and len(operation["targets"]) == count
    assert commit().json()["id"] == operation["id"]
    assert sum(item["action"] == "apply" for item in bridge.calls) == 1
    op = {**context, "operation_id": operation["id"]}
    assert {item["state"] for item in client.post(BASE + "operation", json=op).json()["targets"]} == {"accepted"}
    ids = [item["vm_id"] for item in operation["targets"]]
    assert client.post(BASE + "resolve", json={**op, "vm_ids": ids, "confirm": True}).status_code == 409
    assert client.post(BASE + "forget", json={**op, "confirm": True}).status_code == 409
    with pytest.raises(ValueError, match="unfinished"):
        quiescent(service.store.db)
    bridge.finished = True
    assert {item["state"] for item in client.post(BASE + "operation", json=op).json()["targets"]} == {"observed"}
    quiescent(service.store.db)
    assert client.post(BASE + "history", json=context).json()["operations"][0]["outcomes"] == {"observed": count}
    assert client.delete(f"/api/v1/nodes/{NODE}").json()["error"]["code"] == "vm_retained"
    assert client.delete(f"/api/v1/nodes/{NODE}/proxmox-profile").status_code == 409
    assert client.delete("/api/v1/modules/" + digest).status_code == 409
    current = service.workspaces.get(context["workspace_id"])
    assert client.delete("/api/v1/workspaces/" + current["id"], params={"revision": current["revision"]}).status_code == 409
    path = tmp_path / "backup.sqlite3"
    with sqlite3.connect(path) as copy:
        service.store.db.backup(copy)
    sanitize(path, restored=True)
    with sqlite3.connect(path) as copy:
        restored = json.loads(copy.execute("SELECT value FROM module_proxmox_profiles").fetchone()[0])
        assert restored["enabled"] is False and restored["revision"] == 2
        assert copy.execute("SELECT count(*) FROM module_grants").fetchone()[0] == 0
    service.modules.set_enabled(digest, True, grants[:2])
    assert client.post(BASE + "forget", json={**op, "confirm": True}).status_code == 403
    service.modules.set_enabled(digest, True, grants)
    assert client.post(BASE + "forget", json={**op, "confirm": True}).json() == {"removed": True}
    assert client.post(BASE + "history", json=context).json() == {"operations": []}
    assert client.delete(f"/api/v1/nodes/{NODE}/proxmox-profile").json() == {"removed": True}
    assert commit().status_code == 409
    assert sum(item["action"] == "apply" for item in bridge.calls) == 1


def test_ambiguous_provider_identity_refuses_before_dispatch(console, tmp_path, monkeypatch):
    client, service = console
    context, preview, provider, _, _ = libvirt_fixture(console, tmp_path, monkeypatch, 1)
    service.proxmox.previews[preview["preview_id"]] = service.vms.previews[preview["preview_id"]].copy()
    body = {**context, "preview_id": preview["preview_id"]}
    assert client.post(BASE + "preview", json=body).json()["error"]["code"] == "vm_identity_conflict"
    assert client.post(BASE + "commit", json={**body, "confirm": True}, headers={"Idempotency-Key": "ambiguous-key-00001"}).status_code == 409
    assert provider.calls == []
