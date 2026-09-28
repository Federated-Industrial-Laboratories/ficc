# SPDX-License-Identifier: Apache-2.0
"""Reject recycled Proxmox identities and unqualified privileged protocols."""

import copy
import uuid

import pytest
from ficc_node import proxmox_compat, proxmox_spec
from ficc_node.vm_libvirt import ProviderError


def provider():
    return {"version": "pve-manager/9.2.0/0123456789abcdef", "fingerprint": "a" * 64,
            "node": "fixture", "machine_id": "b" * 32}


def identity(vmid):
    return proxmox_spec.birth(vmid, str(uuid.UUID(int=vmid)), str(uuid.UUID(int=vmid + 1)), "b" * 32)


def request(size=1):
    return {"version": 1, "action": "apply", "connection": "local", "profile": "c" * 32,
            "provider": provider(), "parameters": {"controller": "d" * 32, "operation": "e" * 32,
                "intent": {"action": "start", "expected": [
                    {"uuid": identity(index + 100), "definition": "f" * 64, "state": "off"} for index in range(size)]}}}


@pytest.mark.parametrize("size", [1, 64])
def test_batch_protocol_and_birth_changes(size):
    value = request(size)
    assert proxmox_spec.request(value) == value
    for index, selected in enumerate(value["parameters"]["intent"]["expected"]):
        vmid = index + 100
        assert proxmox_spec.vmid(selected["uuid"]) == vmid
        for machine, smbios, generation in (("0" * 32, vmid, vmid + 1),
                                            ("b" * 32, vmid + 1, vmid + 1),
                                            ("b" * 32, vmid, vmid + 2)):
            assert proxmox_spec.birth(vmid, str(uuid.UUID(int=smbios)), str(uuid.UUID(int=generation)), machine) != selected["uuid"]
    assert len(proxmox_spec.encode(value)) < 1024 * 1024


@pytest.mark.parametrize("mutation", ["uri", "command", "skiplock", "version", "duplicate", "vmid", "fields"])
@pytest.mark.parametrize("size", [1, 64])
def test_fixed_authority_rejects_request_overrides(size, mutation):
    value = request(size)
    if mutation == "uri":
        value["connection"] = "https://other.invalid:8006"
    elif mutation in {"command", "skiplock"}:
        value["parameters"][mutation] = True
    elif mutation == "version":
        value["provider"]["version"] = "pve-manager/10.0.0/01234567"
    elif mutation == "duplicate":
        value["parameters"]["intent"]["expected"].append(copy.deepcopy(value["parameters"]["intent"]["expected"][0]))
    elif mutation == "vmid":
        value["parameters"]["intent"]["expected"][-1]["uuid"] = "0" * 32
    else:
        value["provider"]["credentials"] = "not-allowed"
    with pytest.raises(ValueError):
        proxmox_spec.request(value)


@pytest.mark.parametrize("bad", [None, "", "0" * 32, str(uuid.UUID(int=0)), "../../other"])
def test_both_provider_birth_identifiers_required(bad):
    for first, second in ((bad, str(uuid.UUID(int=1))), (str(uuid.UUID(int=1)), bad)):
        with pytest.raises(ValueError):
            proxmox_spec.birth(100, first, second, "a" * 32)


@pytest.mark.parametrize("size", [1, 64])
def test_task_identity_is_exactly_bound(size):
    for index in range(size):
        value = {"upid": f"UPID:fixture:00000001:00000002:00000003:ficcvmstart:{index + 100}:root@pam:",
                 "state": "stopped", "exitstatus": "OK"}
        assert proxmox_spec.task(value, node="fixture", expected_vmid=index + 100, action="start") == value
        for check in ({"node": "other"}, {"expected_vmid": index + 101}, {"action": "shutdown"}):
            with pytest.raises(ValueError):
                proxmox_spec.task(value, **check)
        value["state"] = "running"
        with pytest.raises(ValueError):
            proxmox_spec.task(value)


def test_power_remains_closed_until_exact_build_qualification(monkeypatch):
    monkeypatch.setattr(proxmox_compat, "POWER_BUILDS", frozenset())
    with pytest.raises(ProviderError, match="no qualified"):
        proxmox_compat.require_power(provider())
    monkeypatch.setattr(proxmox_compat, "discover", provider)
    with pytest.raises(ProviderError, match="no qualified"):
        proxmox_compat.require_provider(provider())
    monkeypatch.setattr(proxmox_compat, "READ_BUILDS", frozenset({(provider()["version"], provider()["fingerprint"])}))
    assert proxmox_compat.require_provider(provider()) == provider()
    changed = provider() | {"fingerprint": "f" * 64}
    with pytest.raises(ProviderError, match="changed"):
        proxmox_compat.require_provider(changed)
