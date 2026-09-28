# SPDX-License-Identifier: Apache-2.0
"""Detect Proxmox task identity, durable recovery and module authority defects."""

import copy

import pytest
from ficc_node import proxmox_rpc, proxmox_spec, proxmox_state
from ficc_node.vm_libvirt import ProviderError
from test_module_proxmox_protocol import identity, provider
from test_module_vm import DIGEST, call, setup

from ficc import module_proxmox
from ficc.errors import Failure
from ficc.module_proxmox import Proxmox
from ficc.providers.proxmox import validate


def request(size, action="apply"):
    return {"version": 1, "connection": "local", "profile": "a" * 32, "provider": provider(), "action": action,
        "parameters": {"controller": "c" * 32, "operation": "d" * 32,
            "intent": {"action": "start", "expected": [
                {"uuid": identity(100 + index), "state": "off", "definition": "f" * 64} for index in range(size)]}}}


class Bridge:
    def __init__(self, size):
        self.size, self.calls, self.finished, self.failure, self.lost = size, [], False, False, False
        self.rows = {identity(100 + index): {"uuid": identity(100 + index), "state": "off", "definition": "f" * 64,
            "name": f"VM {index}", "vcpus": 1, "memory_kib": 0, "max_memory_kib": 131072} for index in range(size)}

    def __call__(self, value):
        action, params = value["action"], value["parameters"]
        self.calls.append(copy.deepcopy(value))
        if action == "tasks":
            return {"tasks": [{"upid": upid, "state": "stopped" if self.finished else "running",
                **({"exitstatus": "FICC_VM_CHANGED" if self.failure else "OK"} if self.finished else {})}
                for upid in params["upids"]]}
        if action == "apply":
            rows = []
            for item in params["intent"]["expected"]:
                vmid = proxmox_spec.vmid(item["uuid"])
                self.rows[item["uuid"]]["state"] = "running"
                rows.append({"uuid": item["uuid"], "state": "accepted", "task": {
                    "upid": f"UPID:fixture:00000001:00000002:00000003:ficcvmstart:{vmid}:root@pam:", "state": "running"}})
            if self.lost:
                raise ProviderError("proxmox_timeout", "Lost task result.")
            return {"results": rows}
        ids = params["uuids"] if action == "status" else list(self.rows)[params["offset"]:params["offset"] + params["limit"]]
        result = {"results": [{"uuid": item, "data": copy.deepcopy(self.rows[item])} for item in ids]}
        if action == "list":
            end = params["offset"] + len(ids)
            result.update(total=self.size, next_offset=end if end < self.size else None,
                          truncated=end < self.size, inventory_digest="e" * 64)
        return result


def node(tmp_path, monkeypatch, size):
    bridge = Bridge(size)
    monkeypatch.setattr(proxmox_state.files, "root", lambda: tmp_path)
    monkeypatch.setattr(proxmox_state, "require_power", lambda _: None)
    monkeypatch.setattr(proxmox_state, "run", bridge)
    monkeypatch.setattr(proxmox_rpc, "run", bridge)
    monkeypatch.setattr(proxmox_rpc, "require_provider", lambda _: provider())
    monkeypatch.setattr(proxmox_rpc, "discover", provider)
    monkeypatch.setattr(module_proxmox, "require_power", lambda _: None)
    monkeypatch.setattr(module_proxmox, "require_read", lambda _: None)
    return bridge


@pytest.mark.parametrize("size", [1, 64])
@pytest.mark.parametrize("failure", [False, True])
def test_exact_tasks_recovery_and_terminal_cleanup(tmp_path, monkeypatch, size, failure):
    bridge = node(tmp_path, monkeypatch, size)
    value = request(size)
    first = proxmox_rpc.dispatch(value)
    assert validate(first, value) == first
    again = proxmox_rpc.dispatch(value)
    assert again == first and sum(item["action"] == "apply" for item in bridge.calls) == 1
    bridge.finished, bridge.failure = True, failure
    value["action"] = "receipt"
    terminal = proxmox_rpc.dispatch(value)
    assert {item["state"] for item in terminal["results"]} == ({"failed"} if failure else {"accepted"})
    validate(terminal, value)
    value["action"] = "forget"
    value["parameters"]["outcomes"] = [{"uuid": item["uuid"], "state": "failed" if failure else "observed"}
                                        for item in terminal["results"]]
    def no_provider(_):
        raise AssertionError("Terminal cleanup must not call the provider.")
    monkeypatch.setattr(proxmox_rpc, "require_provider", no_provider)
    monkeypatch.setattr(proxmox_state, "run", no_provider)
    assert proxmox_rpc.dispatch(value) == {"removed": True}
    assert proxmox_rpc.dispatch(value) == {"removed": True}


@pytest.mark.parametrize("size", [1, 64])
def test_lost_task_result_does_not_dispatch_again(tmp_path, monkeypatch, size):
    bridge = node(tmp_path, monkeypatch, size)
    bridge.lost = True
    value = request(size)
    result = proxmox_rpc.dispatch(value)
    assert {item["state"] for item in result["results"]} == {"unknown"}
    assert proxmox_rpc.dispatch(value) == result
    assert sum(item["action"] == "apply" for item in bridge.calls) == 1
    changed = copy.deepcopy(value)
    changed["provider"]["fingerprint"] = "e" * 64
    with pytest.raises(ProviderError, match="different"):
        proxmox_rpc.dispatch(changed)


@pytest.mark.parametrize("size", [1, 64])
async def test_host_batch_requires_task_completion_and_current_grants(tmp_path, monkeypatch, size):
    original, _, denied, _ = setup(tmp_path, monkeypatch, size)
    bridge = node(tmp_path, monkeypatch, size)
    service = original.service

    async def command(node, command, payload, check, timeout):
        check()
        result = proxmox_rpc.dispatch(proxmox_spec.decode(payload))
        check()
        return 0, proxmox_spec.encode({"version": 1, "data": result}), b""

    service.ssh.command = command
    vms = Proxmox(service)
    profile = await vms.set_profile("owner", "node-0")
    selected = [vms.resource_id(profile["id"], item) for item in bridge.rows]
    listing = await vms.broker("owner", call("vm.proxmox.list", ["node-0"], {}), "instance")
    assert len(listing[0]["data"]["results"]) == size
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": selected}, lambda: None)
    result = await vms.commit("owner", preview["preview_id"], "proxmox-runtime-0001", lambda: None)
    assert result["provider"] == "proxmox"
    observed = await vms.operation("owner", result["id"], lambda: None)
    assert {item["state"] for item in observed["targets"]} == {"accepted"}
    with pytest.raises(Failure, match="stopped provider task"):
        await vms.resolve("owner", result["id"], selected, lambda: None)
    denied.add(("vm:read", "node-0"))
    with pytest.raises(Failure, match="Denied"):
        await vms.operation("owner", result["id"], lambda: None)
    denied.clear()
    bridge.finished = True
    observed = await vms.operation("owner", result["id"], lambda: None)
    assert {item["state"] for item in observed["targets"]} == {"observed"}
    assert await vms.forget("owner", result["id"], lambda: None) == {"removed": True}
    assert await vms.remove_profile("owner", "node-0") == {"removed": True}
