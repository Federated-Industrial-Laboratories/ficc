# SPDX-License-Identifier: Apache-2.0
"""Keep intent-bound receipt removal recoverable without replaying VM actions."""

import asyncio
import copy
from pathlib import Path

import pytest
from ficc_node import vm_rpc, vm_spec, vm_state
from ficc_node.vm_libvirt import ProviderError
from test_module_vm import DIGEST, FakeProvider, ids, setup

from ficc.errors import Failure
from ficc.module_vm import VMs
from ficc.module_vm_store import operation, validate_records
from ficc.providers.libvirt import validate


async def completed(vms, selected, nodes):
    preview = await vms.preview("owner", DIGEST, "instance", nodes,
                               {"action": "start", "vm_ids": selected}, lambda: None)
    value = await vms.commit("owner", preview["preview_id"], "cleanup-test-key-0001", lambda: None)
    value = await vms.operation("owner", value["id"], lambda: None)
    assert {item["state"] for item in value["targets"]} == {"observed"}
    return value, preview


@pytest.mark.parametrize("size", [1, 64])
async def test_remove_receipt_then_profile_without_replay(tmp_path, monkeypatch, size):
    vms, provider, denied, _ = setup(tmp_path, monkeypatch, size)
    value, preview = await completed(vms, ids(vms, size), ["node-0"])
    with pytest.raises(Failure, match="receipts"):
        await vms.remove_profile("owner", "node-0")
    with pytest.raises(Failure, match="receipts"):
        vms.set_profile("owner", "node-0", "system", False)
    vms.set_profile("owner", "node-0", "session", False)
    vms.set_profile("owner", "node-0", "session")
    denied.add(("vm:read", "node-0"))
    with pytest.raises(Failure):
        await vms.forget("owner", value["id"], lambda: None)
    assert "cleanup" not in vms.records.get(value["id"])
    denied.clear()
    assert await vms.forget("owner", value["id"], lambda: None) == {"removed": True}
    assert not vms.records.all() and not list((tmp_path / "receipts").glob("*.json"))
    with pytest.raises(Failure, match="expired"):
        await vms.commit("owner", preview["preview_id"], "cleanup-test-key-0001", lambda: None)
    assert len(provider.calls) == size
    assert await vms.remove_profile("owner", "node-0") == {"removed": True}
    assert not vms.records.retained("node-0")


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("fault", ["lost_ack", "cancel", "revoke"])
async def test_cleanup_partial_ack_restart_and_exact_retry(tmp_path, monkeypatch, count, fault):
    vms, _, denied, nodes = setup(tmp_path, monkeypatch, 1, count)
    providers = {node: FakeProvider(1) for node in nodes}
    roots = {node: tmp_path / node for node in nodes}
    for root in roots.values():
        root.mkdir(mode=0o700)
    requests, stalled = [], asyncio.Event()
    failed, cleanup = False, False
    last = f"node-{count - 1}"

    async def command(node, command, payload, check, timeout):
        nonlocal failed
        check()
        request = vm_spec.decode(payload)
        requests.append((node["id"], request["action"]))
        monkeypatch.setattr(vm_state, "root", lambda: roots[node["id"]])
        monkeypatch.setattr(vm_rpc, "Libvirt", lambda *args, **kwargs: providers[node["id"]])
        result = vm_rpc.dispatch(request)
        if cleanup and node["id"] == last and not failed and request["action"] == "forget":
            failed = True
            if fault == "cancel":
                stalled.set()
                await asyncio.Event().wait()
            elif fault == "revoke":
                denied.add(("vm:power", last))
                check()
            raise Failure("unreachable", "Acknowledgement lost.", 502)
        check()
        return 0, vm_spec.encode({"version": 1, "data": result}), b""

    vms.service.ssh.command = command
    selected = [f"libvirt-{vms.records.profile(node)['id']}-{'0' * 32}" for node in nodes]
    value, _ = await completed(vms, selected, list(nodes))
    cleanup = True
    task = asyncio.create_task(vms.forget("owner", value["id"], lambda: None))
    if fault == "cancel":
        await stalled.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(Failure, match="not acknowledged"):
            await task
    retained = vms.records.get(value["id"])
    assert len(retained["cleanup"]) == count - 1
    assert all(not list(root.glob("*.json")) for root in roots.values())
    assert all(vms.records.retained(node) for node in nodes)
    with pytest.raises(ValueError, match="unfinished"):
        validate_records(list(vms.service.store.db.execute("SELECT * FROM module_vm_profiles")),
                         list(vms.service.store.db.execute("SELECT * FROM module_vm_operations")), set(nodes))
    vms = VMs(vms.service)
    denied.clear()
    before = len(requests)
    public = await vms.operation("owner", value["id"], lambda: None)
    assert public["cleanup"] == {"acknowledged": count - 1, "total": count}
    assert len(requests) == before
    assert await vms.forget("owner", value["id"], lambda: None) == {"removed": True}
    assert requests[before:] == [(last, "forget")]
    assert sum(len(provider.calls) for provider in providers.values()) == count
    assert not vms.records.all()


@pytest.mark.parametrize("size", [1, 64])
@pytest.mark.parametrize("state", ["queued", "dispatching", "accepted", "unknown"])
async def test_nonterminal_cleanup_refused_before_remote_call(tmp_path, monkeypatch, size, state):
    vms, _, _, _ = setup(tmp_path, monkeypatch, size)
    value, _ = await completed(vms, ids(vms, size), ["node-0"])
    stored = vms.records.get(value["id"])
    stored["targets"][-1]["state"] = state
    vms.records.save(stored)
    before = len(vms.service.ssh.calls)
    with pytest.raises(Failure, match="resolve every outcome"):
        await vms.forget("owner", value["id"], lambda: None)
    assert len(vms.service.ssh.calls) == before
    assert "cleanup" not in vms.records.get(value["id"])


def remote_request(size):
    return {"version": 1, "action": "forget", "profile": "a" * 32, "connection": "session",
            "parameters": {"controller": "b" * 32, "operation": "c" * 32,
                "intent": {"action": "start", "expected": [
                    {"uuid": f"{index:032x}", "state": "off", "definition": "d" * 64} for index in range(size)]},
                "outcomes": [{"uuid": f"{index:032x}", "state": "observed"} for index in range(size)]}}


def remote_receipt(tmp_path, request, state="accepted"):
    path = tmp_path / ("b" * 32 + "-" + "c" * 32 + ".json")
    identity = {key: request[key] for key in ("profile", "connection")}
    identity["intent"] = request["parameters"]["intent"]
    value = {"digest": vm_spec.digest(identity), "results": [
        {"uuid": item["uuid"], "state": state} for item in request["parameters"]["outcomes"]]}
    vm_state.write(path, value)
    return path


@pytest.mark.parametrize("size", [1, 64])
def test_node_terminal_proof_survives_interrupted_unlink(tmp_path, monkeypatch, size):
    request = remote_request(size)
    path = remote_receipt(tmp_path, request)
    monkeypatch.setattr(vm_state, "root", lambda: tmp_path)
    original = Path.unlink

    def fail_unlink(self, *args, **kwargs):
        if self == path:
            raise OSError("Simulated interrupted unlink.")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", fail_unlink)
    with pytest.raises(OSError):
        vm_rpc.dispatch(request)
    assert {item["state"] for item in vm_state.read(path)["results"]} == {"observed"}
    replay = copy.deepcopy(request)
    replay["action"] = "apply"
    replay["parameters"].pop("outcomes")
    with pytest.raises(ProviderError, match="removal has started"):
        vm_state.receipt(None, replay)
    monkeypatch.setattr(Path, "unlink", original)
    monkeypatch.setattr(vm_rpc, "Libvirt", lambda *args, **kwargs: pytest.fail("Cleanup must not open libvirt."))
    assert validate(vm_rpc.dispatch(request), request) == {"removed": True}
    assert vm_rpc.dispatch(request) == {"removed": True}
    assert not path.exists()


@pytest.mark.parametrize("size", [1, 64])
@pytest.mark.parametrize("mutation", ["identity", "intent", "profile", "unknown", "outcomes"])
def test_node_forget_rejects_forged_terminal_proof(tmp_path, monkeypatch, size, mutation):
    request = remote_request(size)
    path = remote_receipt(tmp_path, request, "unknown" if mutation == "unknown" else "accepted")
    before = path.read_bytes()
    monkeypatch.setattr(vm_state, "root", lambda: tmp_path)
    if mutation == "identity":
        request["parameters"]["outcomes"][-1]["uuid"] = "f" * 32
    elif mutation == "intent":
        request["parameters"]["intent"]["expected"][-1]["definition"] = "e" * 64
    elif mutation == "profile":
        request["profile"] = "f" * 32
    elif mutation == "outcomes":
        request["parameters"]["outcomes"][-1]["state"] = "accepted"
    with pytest.raises((ValueError, ProviderError)):
        vm_rpc.dispatch(request)
    assert path.read_bytes() == before


@pytest.mark.parametrize("mutation", ["duplicate", "foreign", "nonterminal", "not-list"])
async def test_cleanup_record_validation(tmp_path, monkeypatch, mutation):
    vms, _, _, _ = setup(tmp_path, monkeypatch)
    value, _ = await completed(vms, ids(vms, 1), ["node-0"])
    stored = vms.records.get(value["id"])
    pid = stored["targets"][0]["profile"]["id"]
    stored["cleanup"] = [pid]
    if mutation == "duplicate":
        stored["cleanup"] *= 2
    elif mutation == "foreign":
        stored["cleanup"] = ["f" * 32]
    elif mutation == "nonterminal":
        stored["targets"][0]["state"] = "unknown"
    else:
        stored["cleanup"] = {pid: True}
    with pytest.raises(ValueError, match="cleanup"):
        operation(stored)


async def test_forged_multi_profile_system_batch_is_rejected(tmp_path, monkeypatch):
    vms, _, _, _ = setup(tmp_path, monkeypatch, 2)
    value, _ = await completed(vms, ids(vms, 2), ["node-0"])
    stored = vms.records.get(value["id"])
    target = stored["targets"][-1]
    target["profile"]["id"] = "f" * 32
    target["vm_id"] = f"libvirt-{'f' * 32}-{target['expected']['uuid']}"
    frozen = [{key: target[key] for key in ("node_id", "profile", "vm_id", "expected")} | {"state": "queued"}
              for target in stored["targets"]]
    stored["digest"] = vm_spec.digest({"preview_id": stored["preview_id"], "action": stored["action"], "targets": frozen})
    with pytest.raises(ValueError, match="Conflicting"):
        operation(stored)
