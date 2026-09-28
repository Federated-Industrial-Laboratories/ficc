# SPDX-License-Identifier: Apache-2.0
"""Opt-in real libvirt and RFB qualification on the sealed disposable guest."""

import secrets

import pytest
from test_module_vm_live_support import checked, rfb_handshake
from test_module_vm_live_support import live_vm as live_vm

from ficc.errors import Failure
from ficc.providers.libvirt import COMMAND


def test_live_readonly_inventory_and_domain_bound_rfb(live_vm):
    live = live_vm
    rows = live.fixture_rows()
    assert rows["ficc-vm-a"]["values"]["state"] == "running"
    assert rows["ficc-vm-b"]["values"]["state"] == "off"
    denied = live.invoke("preview-start", {"vm_ids": [rows["ficc-vm-b"]["id"]]}, status=403)
    assert denied["error"]["code"] == "denied"
    live.invoke("open-console", {"vm_ids": [rows["ficc-vm-a"]["id"]]}, status=403)
    grants = live.grants + [{"capability": "vm:console", "target_ids": [live.node["id"]]}]
    live.activate(grants)

    def guard():
        live.service.authorize(live.actor, "vm:console", live.node["id"])
        live.service.modules.require(live.digest, "workspace:read", [live.context["workspace_id"]])
    descriptor = live.client.portal.call(live.service.vms.console, live.actor, live.digest,
        live.context["instance_id"], live.node["id"], rows["ficc-vm-a"]["id"], guard)
    assert descriptor["graphics"]["audio"] is False
    assert not {"address", "password", "port"} & descriptor["graphics"].keys()
    argv, header = live.client.portal.call(live.service.vms.console_command, descriptor, guard)
    assert rfb_handshake(argv, header) == "RFB 003.008"
    live.activate(live.grants)
    with pytest.raises(Failure):
        live.client.portal.call(live.service.vms.console_command, descriptor, guard)
    assert live.fixture_rows()["ficc-vm-a"]["values"]["state"] == "running"


def test_live_inventory_64_inactive_definitions_and_cleanup(live_vm):
    live = live_vm
    live.fixture_rows()
    prefix = "ficc-qual-" + secrets.token_hex(4)
    try:
        assert live.definitions(prefix, "create") == {"count": 64, "active": 1}
        first = live.inventory()
        assert len(first["rows"]) == 64 and "offset 64" in first["notice"]
        second = live.inventory(64)
        assert len(second["rows"]) == 2 and not second["notice"]
        selected = [row for row in first["rows"] + second["rows"] if row["values"]["name"].startswith(prefix + "-")]
        assert len(selected) == 64 and len({row["id"] for row in selected}) == 64
        assert {row["values"]["state"] for row in selected} == {"off"}
        profile = live.service.vms.records.profile(live.node["id"])
        result = live.client.portal.call(live.service.vms.transport.request, live.node, profile,
            "status", {"uuids": [row["id"].rsplit("-", 1)[1] for row in selected]}, lambda: None)
        assert len(result["results"]) == 64 and all("data" in row for row in result["results"])
    finally:
        assert live.definitions(prefix, "cleanup") == {"count": 0, "active": 1}
        live.fixture_rows()


def test_live_host_confirmation_lifecycle_no_replay_and_revocation(live_vm, monkeypatch):
    live = live_vm
    rows = live.fixture_rows()
    vm_id = rows["ficc-vm-b"]["id"]
    assert rows["ficc-vm-b"]["values"]["state"] == "off"
    grants = live.grants + [{"capability": "vm:power", "target_ids": [live.node["id"]]}]
    live.activate(grants)
    preview = live.preview("start", vm_id)
    live.activate(live.grants)
    live.commit(preview, status=403)
    assert live.fixture_rows()["ficc-vm-b"]["values"]["state"] == "off"
    live.activate(grants)
    previous = live.service.ssh.command
    dispatched = []

    async def observe(node, command, payload=b"", check=None, timeout=10):
        if command == COMMAND:
            from ficc_node.vm_spec import decode
            message = decode(payload)
            if message["action"] == "apply":
                dispatched.append(message["parameters"]["operation"])
        return await previous(node, command, payload, check=check, timeout=timeout)
    monkeypatch.setattr(live.service.ssh, "command", observe)
    started = None
    boot_offset = live.boot_marker()["offset"]
    try:
        preview = live.preview("start", vm_id)
        assert preview["vms"][0]["state"] == "off"
        body = {**live.context, "preview_id": preview["preview_id"], "confirm": False}
        checked(live.client.post("/api/v1/module-vms/commit", json=body,
                headers={"Idempotency-Key": secrets.token_hex(16)}), 422)
        assert not dispatched
        key = secrets.token_hex(16)
        started = live.commit(preview, key)
        assert started["targets"][0]["state"] == "accepted"
        assert live.commit(preview, key)["id"] == started["id"]
        assert len(dispatched) == 1
        observed = live.wait_operation(started["id"])
        assert observed["targets"][0]["state"] == "observed"
        assert live.fixture_rows()["ficc-vm-b"]["values"]["state"] == "running"
        live.wait_boot(boot_offset)
        preview = live.preview("shutdown", vm_id)
        shutdown = live.commit(preview)
        assert shutdown["targets"][0]["state"] == "accepted"
        observed = live.wait_operation(shutdown["id"])
        assert observed["targets"][0]["observed_state"] == "off"
        assert len(dispatched) == 2
    finally:
        current = live.fixture_rows()["ficc-vm-b"]["values"]["state"]
        if started and current != "off":
            # Cleanup remains a confirmed graceful action, never force-off.
            unresolved = [item for item in live.service.vms.records.all()
                          if any(target["state"] not in {"observed", "refused", "resolved"} for target in item["targets"])]
            for item in unresolved:
                live.wait_operation(item["id"])
            shutdown = live.commit(live.preview("shutdown", vm_id))
            live.wait_operation(shutdown["id"])
        assert live.fixture_rows()["ficc-vm-a"]["values"]["state"] == "running"
        assert live.fixture_rows()["ficc-vm-b"]["values"]["state"] == "off"
