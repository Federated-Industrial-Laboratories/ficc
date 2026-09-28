# SPDX-License-Identifier: Apache-2.0
"""Check complete container confirmation, history, cleanup and restored authority."""

import json
import secrets
import sqlite3

import pytest
from conftest import node
from ficc_node import container_rpc, container_state
from ficc_node import container_spec as spec
from test_module_containers import Provider
from test_modules_packages import bundle, package

from ficc.backup_database import quiescent, sanitize
from ficc.module_broker import handler
from ficc.modules import inspect_archive
from ficc.modules.broker_protocol import BrokerCall
from ficc.workspace_schema import WorkspaceUpdate

BASE = "/api/v1/module-containers/"
NODE = "0" * 32


def fixture(console, tmp_path, monkeypatch, count):
    client, service = console
    service.store.save_node({**node(), "id": NODE})
    actor = service.auth.resolve(client.cookies.get("ficc_session")).id
    provider = Provider(count)
    monkeypatch.setattr(container_rpc, "Engine", lambda *args: provider)
    receipts = tmp_path / "node-receipts"
    receipts.mkdir(mode=0o700)
    monkeypatch.setattr(container_state, "root", lambda: receipts)

    async def command(_node, _command, payload, check, timeout):
        check()
        value = container_rpc.dispatch(spec.decode(payload))
        check()
        return 0, spec.encode({"version": 1, "data": value}), b""
    monkeypatch.setattr(service.ssh, "command", command)
    profile = client.put("/api/v1/container-profiles", json={"node_id": NODE, "provider": "docker", "connection": "rootless"})
    assert profile.status_code == 200, profile.text
    workspace = service.workspaces.create("Containers")
    caps = ["workspace:read", "container:read", "container:power", "container:logs"]
    checked = inspect_archive(bundle(*package(capabilities=caps, optional_capabilities=caps[2:])))
    service.modules.install(checked, checked.digest)
    grants = [{"capability": cap, "target_ids": [workspace["id"]] if cap == "workspace:read" else [NODE]} for cap in caps]
    service.modules.set_enabled(checked.digest, True, grants)
    context = {"workspace_id": workspace["id"], "instance_id": secrets.token_hex(16)}
    item = {"id": context["instance_id"], "digest": checked.digest, "title": "Containers", "targets": [NODE]}
    service.workspaces.update(workspace["id"], WorkspaceUpdate(revision=0, name="Containers", instances=[item]))
    call = BrokerCall("1" * 32, "2" * 32, "container.list", (NODE,), {"limit": 256}, checked.digest, "load", tuple(caps), lambda: None)
    result = client.portal.call(handler(service, actor, context["instance_id"]), call)
    ids = [row["resource_id"] for row in result[0]["data"]["profiles"][0]["data"]["results"]]
    preview = client.portal.call(service.containers.preview, actor, checked.digest, context["instance_id"], [NODE],
                                 {"action": "start", "resource_ids": ids}, lambda: None)
    return context, preview, profile.json(), provider, checked.digest, grants


def retained(client, service, context, digest, profile):
    current = service.workspaces.get(context["workspace_id"])
    route = "/api/v1/workspaces/" + current["id"]
    assert client.delete(route, params={"revision": current["revision"]}).status_code == 409
    assert client.put(route, json={"name": current["name"], "revision": current["revision"], "instances": []}).status_code == 409
    assert client.delete("/api/v1/modules/" + digest).status_code == 409
    assert client.delete("/api/v1/container-profiles/" + profile["id"]).status_code == 409
    renamed = client.put(route, json={"name": "Renamed", "revision": current["revision"], "instances": current["instances"]})
    assert renamed.status_code == 200


@pytest.mark.parametrize("count", [1, 64])
def test_complete_confirmation_history_retention_restore_and_cleanup(console, tmp_path, monkeypatch, count):
    client, service = console
    context, preview, profile, provider, digest, grants = fixture(console, tmp_path, monkeypatch, count)
    body = {**context, "preview_id": preview["preview_id"]}
    assert client.post(BASE + "preview", json=body).json() == preview
    key = secrets.token_hex(16)
    headers = {"Idempotency-Key": key}
    assert client.post(BASE + "commit", json={**body, "confirm": True}, headers={**headers, "X-CSRF-Token": "bad"}).status_code == 403
    assert client.post(BASE + "commit", json={**body, "confirm": False}, headers=headers).status_code == 422
    assert provider.calls == []
    result = client.post(BASE + "commit", json={**body, "confirm": True}, headers=headers)
    assert result.status_code == 200, result.text
    operation = result.json()
    op = {**context, "operation_id": operation["id"]}
    assert len(operation["targets"]) == count and len(provider.calls) == count
    assert client.post(BASE + "commit", json={**body, "confirm": True}, headers=headers).json()["id"] == operation["id"]
    assert len(provider.calls) == count
    assert client.post(BASE + "history", json=context).json()["operations"][0]["outcomes"] == {"accepted": count}
    retained(client, service, context, digest, profile)
    with pytest.raises(ValueError, match="active or unknown"):
        quiescent(service.store.db)
    assert client.post(BASE + "forget", json={**op, "confirm": True}).status_code == 409
    assert client.post(BASE + "operation", json=op).json()["targets"][0]["state"] == "observed"
    retained(client, service, context, digest, profile)
    changed = client.put("/api/v1/container-profiles", json={"node_id": NODE, "provider": "docker", "connection": "rootful", "profile_id": profile["id"]})
    assert changed.status_code == 409
    quiescent(service.store.db)
    path = tmp_path / "snapshot.sqlite3"
    with sqlite3.connect(path) as copied:
        service.store.db.backup(copied)
    sanitize(path, restored=True)
    with sqlite3.connect(path) as copied:
        restored = json.loads(copied.execute("SELECT value FROM module_container_profiles").fetchone()[0])
        assert restored["enabled"] is False and restored["revision"] == 2
        assert copied.execute("SELECT count(*) FROM module_grants").fetchone()[0] == 0
    service.modules.set_enabled(digest, True, grants[:2])
    assert client.post(BASE + "forget", json={**op, "confirm": True}).status_code == 403
    assert client.post(BASE + "history", json=context).status_code == 200
    service.modules.set_enabled(digest, False)
    assert client.post(BASE + "history", json=context).status_code == 403
    service.modules.set_enabled(digest, True, grants)
    assert client.post(BASE + "forget", json={**op, "confirm": True}).json() == {"removed": True}
    assert not list((tmp_path / "node-receipts").glob("*.json"))
    assert client.post(BASE + "history", json=context).json() == {"operations": []}
    assert client.post(BASE + "commit", json={**body, "confirm": True}, headers=headers).status_code == 409
    assert len(provider.calls) == count
    assert client.delete("/api/v1/container-profiles/" + profile["id"]).json() == {"removed": True}
    current = service.workspaces.get(context["workspace_id"])
    assert client.delete("/api/v1/workspaces/" + current["id"], params={"revision": current["revision"]}).status_code == 200
    assert client.delete("/api/v1/modules/" + digest).status_code == 200


def test_changed_panel_invalid_profile_and_history_scope(console, tmp_path, monkeypatch):
    client, service = console
    context, preview, _, provider, digest, grants = fixture(console, tmp_path, monkeypatch, 1)
    assert client.delete("/api/v1/container-profiles/invalid").status_code == 422
    assert client.put("/api/v1/container-profiles", json={"node_id": NODE, "provider": "podman", "connection": "rootful"}).status_code == 400
    service.modules.set_enabled(digest, True, grants[:2])
    body = {**context, "preview_id": preview["preview_id"], "confirm": True}
    assert client.post(BASE + "commit", json=body, headers={"Idempotency-Key": secrets.token_hex(16)}).status_code == 403
    assert provider.calls == []
    service.modules.set_enabled(digest, True, grants)
    workspace = service.workspaces.get(context["workspace_id"])
    service.workspaces.update(workspace["id"], WorkspaceUpdate(revision=workspace["revision"], name="Containers", instances=[]))
    assert client.post(BASE + "commit", json=body, headers={"Idempotency-Key": secrets.token_hex(16)}).status_code == 409
    assert client.post(BASE + "history", json=context).status_code == 404
    assert provider.calls == []
