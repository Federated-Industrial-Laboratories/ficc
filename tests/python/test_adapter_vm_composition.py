# SPDX-License-Identifier: Apache-2.0
"""Verify installed adapter VM calls, host confirmation and explicit local receipt removal."""

import secrets

import pytest
from conftest import node
from test_module_adapter_manifest import adapter_package
from test_module_adapter_vm import Provider
from test_module_adapters import Transport
from test_modules_packages import bundle, package

from ficc.backup_database import quiescent
from ficc.module_broker import handler
from ficc.modules import inspect_archive
from ficc.modules.broker_protocol import BrokerCall


@pytest.mark.parametrize("count", [1, 64])
def test_adapter_broker_host_confirmation_history_and_orphan_cleanup(console, count):
    client, service = console
    node_id = "d" * 32
    service.store.save_node({**node(), "id": node_id})
    actor = service.auth.resolve(client.cookies.get("ficc_session")).id
    adapter = inspect_archive(bundle(*adapter_package()))
    service.modules.install(adapter, adapter.digest)
    transport, provider = Transport(), Provider(None, count)
    transport.execute, transport.forget = provider.execute, provider.forget
    service.adapters.transport = transport
    response = client.post("/api/v1/adapter-profiles", json={"digest": adapter.digest,
        "endpoint_kind": "linux-ssh", "endpoint_id": node_id, "transport_binding_id": "e" * 32})
    assert response.status_code == 201, response.text
    profile_id = response.json()["id"]
    response = client.post(f"/api/v1/adapter-profiles/{profile_id}/grant", json={"expected_revision": 1, "confirm": True})
    assert response.status_code == 200, response.text
    workspace = service.workspaces.create("VM adapter composition")
    capabilities = ["workspace:read", "vm:read", "vm:power"]
    ui = inspect_archive(bundle(*package(id="org.example.vm-panel", capabilities=capabilities)))
    service.modules.install(ui, ui.digest)
    service.modules.set_enabled(ui.digest, True, [{"capability": capability,
        "target_ids": [workspace["id"] if capability == "workspace:read" else node_id]} for capability in capabilities])
    context = {"workspace_id": workspace["id"], "instance_id": secrets.token_hex(16)}
    response = client.put(f"/api/v1/workspaces/{workspace['id']}", json={"revision": 0,
        "name": workspace["name"], "instances": [{"id": context["instance_id"], "digest": ui.digest,
        "title": "VM panel", "targets": [node_id]}]})
    assert response.status_code == 200, response.text

    def broker(primitive, parameters):
        call = BrokerCall("1" * 32, "2" * 32, primitive, (node_id,), parameters, ui.digest,
            "inspect", tuple(capabilities), lambda: None)
        return client.portal.call(handler(service, actor, context["instance_id"]), call)

    inventory = broker("vm.adapter.list", {"profile_id": profile_id})
    ids = [row["vm_id"] for row in inventory[0]["data"]["results"]]
    assert len(ids) == count
    preview = broker("vm.adapter.preview", {"profile_id": profile_id, "vm_ids": ids, "action": "start"})[0]["data"]
    body = {**context, "preview_id": preview["preview_id"]}
    base = "/api/v1/module-vms/"
    response = client.post(base + "preview", json=body)
    assert response.status_code == 200 and len(response.json()["vms"]) == count
    key = secrets.token_hex(16)
    response = client.post(base + "commit", json={**body, "confirm": True}, headers={"Idempotency-Key": key})
    assert response.status_code == 200, response.text
    operation = response.json()
    assert all(item["state"] == "observed" and item["profile_id"] == profile_id for item in operation["targets"])
    repeated = client.post(base + "commit", json={**body, "confirm": True}, headers={"Idempotency-Key": key})
    assert repeated.json()["id"] == operation["id"]
    assert sum(call["phase"] == "apply" for call in provider.calls) == 1
    quiescent(service.store.db)
    assert client.post(base + "history", json=context).json()["operations"][0]["outcomes"] == {"observed": count}
    assert client.post(f"/api/v1/adapter-profiles/{profile_id}/revoke").status_code == 200
    transport.endpoint = lambda *_: {"id": node_id, "revision": 2, "enabled": False, "machine_identity": "f" * 64}
    removal = {**context, "operation_id": operation["id"], "confirm": True}
    response = client.post(base + "forget", json=removal)
    assert response.status_code == 409 and response.json()["error"]["code"] == "adapter_orphan_ack_required"
    assert not provider.cleaned
    response = client.post(base + "forget", json={**removal, "acknowledge_orphans": True})
    assert response.status_code == 200 and response.json()["orphaned_profiles"] == [profile_id]
    assert not provider.cleaned
    assert client.post(base + "history", json=context).json() == {"operations": []}
