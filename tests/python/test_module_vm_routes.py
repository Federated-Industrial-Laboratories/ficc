# SPDX-License-Identifier: Apache-2.0
"""Verify host VM confirmation, retained records and restored grant removal."""

import json
import secrets
import sqlite3

import pytest
from conftest import node
from ficc_node import vm_rpc, vm_spec, vm_state
from test_module_vm import FakeProvider
from test_modules_packages import bundle, package

from ficc.backup_database import quiescent, sanitize
from ficc.modules import inspect_archive
from ficc.workspace_schema import WorkspaceUpdate


def fixture(console, tmp_path, monkeypatch, count):
    client, service = console
    service.store.save_node({**node(), "id": "0" * 32})
    actor = service.auth.resolve(client.cookies.get("ficc_session")).id
    profile = client.put("/api/v1/nodes/" + "0" * 32 + "/vm-profile", json={"connection": "session"})
    assert profile.status_code == 200, profile.text
    workspace = service.workspaces.create("VMs")
    checked = inspect_archive(bundle(*package(capabilities=["workspace:read", "vm:read", "vm:power"], optional_capabilities=["vm:power"])))
    service.modules.install(checked, checked.digest)
    grants = [{"capability": cap, "target_ids": [workspace["id"]] if cap == "workspace:read" else ["0" * 32]}
              for cap in checked.manifest["capabilities"]]
    service.modules.set_enabled(checked.digest, True, grants)
    context = {"workspace_id": workspace["id"], "instance_id": secrets.token_hex(16)}
    item = {"id": context["instance_id"], "digest": checked.digest, "title": "VMs", "targets": ["0" * 32]}
    service.workspaces.update(workspace["id"], WorkspaceUpdate(revision=0, name="VMs", instances=[item]))
    provider = FakeProvider(count)
    monkeypatch.setattr(vm_rpc, "Libvirt", lambda *args, **kwargs: provider)
    receipts = tmp_path / "node-receipts"
    receipts.mkdir(mode=0o700)
    monkeypatch.setattr(vm_state, "root", lambda: receipts)

    async def command(_node, _command, payload, check, timeout):
        check()
        value = vm_rpc.dispatch(vm_spec.decode(payload))
        check()
        return 0, vm_spec.encode({"version": 1, "data": value}), b""
    monkeypatch.setattr(service.ssh, "command", command)
    ids = [f"libvirt-{profile.json()['id']}-{index:032x}" for index in range(count)]
    preview = client.portal.call(service.vms.preview, actor, checked.digest, context["instance_id"],
                                 ["0" * 32], {"action": "start", "vm_ids": ids}, lambda: None)
    return context, preview, provider, checked.digest, grants


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_host_confirmation_and_snapshot_quiescence(console, tmp_path, monkeypatch, count):
    client, service = console
    context, preview, provider, digest, _ = fixture(console, tmp_path, monkeypatch, count)
    body = {**context, "preview_id": preview["preview_id"]}
    base = "/api/v1/module-vms/"
    assert client.post(base + "preview", json=body).json() == preview
    key = secrets.token_hex(16)
    assert client.post(base + "commit", json={**body, "confirm": True},
                       headers={"X-CSRF-Token": "invalid", "Idempotency-Key": key}).status_code == 403
    assert client.post(base + "commit", json={**body, "confirm": False},
                       headers={"Idempotency-Key": key}).status_code == 422
    assert provider.calls == []
    result = client.post(base + "commit", json={**body, "confirm": True}, headers={"Idempotency-Key": key})
    assert result.status_code == 200, result.text
    operation = result.json()
    assert len(operation["targets"]) == count and len(provider.calls) == count
    again = client.post(base + "commit", json={**body, "confirm": True}, headers={"Idempotency-Key": key})
    assert again.json()["id"] == operation["id"] and again.json()["targets"] == operation["targets"]
    assert len(provider.calls) == count
    with pytest.raises(ValueError, match="unfinished"):
        quiescent(service.store.db)
    result = client.post(base + "operation", json={**context, "operation_id": operation["id"]})
    assert result.status_code == 200 and all(item["state"] == "observed" for item in result.json()["targets"])
    quiescent(service.store.db)
    path = tmp_path / "snapshot.sqlite3"
    with sqlite3.connect(path) as copied:
        service.store.db.backup(copied)
    sanitize(path, restored=True)
    with sqlite3.connect(path) as copied:
        restored = json.loads(copied.execute("SELECT value FROM module_vm_profiles").fetchone()[0])
        assert restored["enabled"] is False and restored["revision"] == 2
        assert copied.execute("SELECT count(*) FROM module_grants").fetchone()[0] == 0
    assert client.post(base + "history", json=context).json()["operations"][0]["outcomes"] == {"observed": count}
    current = service.workspaces.get(context["workspace_id"])
    route = "/api/v1/workspaces/" + current["id"]
    assert client.delete(route, params={"revision": current["revision"]}).status_code == 409
    assert client.put(route, json={"name": "VMs", "revision": current["revision"], "instances": []}).status_code == 409
    assert client.delete("/api/v1/modules/" + digest).status_code == 409
    assert client.delete("/api/v1/nodes/" + "0" * 32 + "/vm-profile").status_code == 409
    assert client.post(base + "forget", json={**context, "operation_id": operation["id"],
        "confirm": True, "acknowledge_orphans": "true"}).status_code == 422
    assert client.post(base + "forget", json={**context, "operation_id": operation["id"],
        "confirm": True, "acknowledge_orphans": True}).status_code == 409
    assert client.post(base + "forget", json={**context, "operation_id": operation["id"], "confirm": True}).json() == {"removed": True}
    assert client.post(base + "history", json=context).json() == {"operations": []}
    assert client.delete("/api/v1/nodes/" + "0" * 32 + "/vm-profile").json() == {"removed": True}
    assert client.post(base + "commit", json={**body, "confirm": True}, headers={"Idempotency-Key": key}).status_code == 409
    assert len(provider.calls) == count


def test_confirmation_rechecks_panel_and_grants(console, tmp_path, monkeypatch):
    client, service = console
    context, preview, provider, digest, grants = fixture(console, tmp_path, monkeypatch, 1)
    body = {**context, "preview_id": preview["preview_id"], "confirm": True}
    service.modules.set_enabled(digest, True, grants[:2])
    denied = client.post("/api/v1/module-vms/commit", json=body, headers={"Idempotency-Key": secrets.token_hex(16)})
    assert denied.status_code == 403 and provider.calls == []
    service.modules.set_enabled(digest, True, grants)
    workspace = service.workspaces.get(context["workspace_id"])
    service.workspaces.update(workspace["id"], WorkspaceUpdate(revision=workspace["revision"], name="VMs", instances=[]))
    denied = client.post("/api/v1/module-vms/commit", json=body, headers={"Idempotency-Key": secrets.token_hex(16)})
    assert denied.status_code == 409 and provider.calls == []
