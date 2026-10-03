# SPDX-License-Identifier: Apache-2.0
"""Detect VM authority, durable intent and bounded batch regressions."""

import asyncio
import copy
import sqlite3
import threading
from types import SimpleNamespace

import pytest
from ficc_node import vm_rpc, vm_spec, vm_state
from ficc_node.vm_libvirt import ProviderError
from provider_batch_fixtures import batched_service

from ficc.errors import Failure
from ficc.module_vm import VMs
from ficc.module_vm_store import initialize, validate_records
from ficc.modules.broker_protocol import BrokerCall
from ficc.state_provider import BoundConnection

DIGEST = "a" * 64


class FakeProvider:
    def __init__(self, size):
        self.rows = {f"{index:032x}": {"uuid": f"{index:032x}", "name": f"VM {index}",
            "state": "off", "vcpus": 1, "memory_kib": 1024, "max_memory_kib": 1024,
            "definition": f"{index:064x}"} for index in range(size)}
        self.calls = []
        self.unknown = False

    def close(self):
        pass

    def inventory(self, offset, limit):
        ids = sorted(self.rows)[offset:offset + limit]
        end = offset + len(ids)
        return {**self.status(ids), "total": len(self.rows), "next_offset": end if end < len(self.rows) else None,
                "truncated": end < len(self.rows), "inventory_digest": "d" * 64}

    def status(self, ids):
        return {"results": [{"uuid": item, "data": copy.deepcopy(self.rows[item])} for item in ids]}

    def apply(self, action, expected):
        if any(self.rows[expected["uuid"]][key] != expected[key] for key in expected):
            return {"state": "refused", "error": {"code": "vm_changed", "message": "Changed."}}
        self.calls.append((action, expected["uuid"]))
        self.rows[expected["uuid"]]["state"] = "running" if action == "start" else "off"
        return {"state": "unknown" if self.unknown else "accepted"}

    def console(self, domain_id):
        return {"uuid": domain_id, "protocol": "vnc", "graphics_index": 0,
                "audio": False, "authentication": "rfb"}


def setup(tmp_path, monkeypatch, size=1, node_count=1):
    class Store:
        db = sqlite3.connect(":memory:", factory=BoundConnection)
        initialize(db)
        lock = threading.RLock()
        settings = {}

        def node(self, node_id):
            if node_id not in nodes:
                raise Failure("not_found", "No node.", 404)
            return copy.deepcopy(nodes[node_id])

        def get_setting(self, name, default):
            return self.settings.get(name, default)

        def set_setting(self, name, value):
            self.settings[name] = value

        def audit(self, *args, **kwargs):
            pass

    nodes = {f"node-{index}": {"id": f"node-{index}", "profile": f"node-{index}", "host": "example.test",
            "account": "operator", "port": 22, "key_type": "ssh-ed25519", "key": "trusted"}
             for index in range(node_count)}
    denied = set()

    def authorize(actor, scope, node_id=None):
        if (scope, node_id) in denied:
            raise Failure("denied", "Denied.", 403)

    def require(digest, capability, targets):
        if digest != DIGEST or any((capability, target) in denied for target in targets):
            raise Failure("denied", "Grant revoked.", 403)

    provider = FakeProvider(size)
    monkeypatch.setattr(vm_rpc, "Libvirt", lambda *args, **kwargs: provider)
    root = tmp_path / "receipts"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(vm_state, "root", lambda: root)

    class SSH:
        calls = []
        lose = False

        async def command(self, node, command, payload, check, timeout):
            check()
            self.calls.append(vm_spec.decode(payload))
            data = vm_rpc.dispatch(vm_spec.decode(payload))
            if self.lose and self.calls[-1]["action"] == "apply":
                raise Failure("unreachable", "Connection lost.", 502)
            check()
            return 0, vm_spec.encode({"version": 1, "data": data}), b""

        async def arguments(self, node):
            return ["ssh", "--", node["profile"]]

    service = SimpleNamespace(store=Store(), ssh=SSH(), authorize=authorize,
                              modules=SimpleNamespace(require=require), live=lambda: None)
    batched_service(service)
    vms = VMs(service)
    for node_id in nodes:
        vms.set_profile("owner", node_id, "session")
    return vms, provider, denied, nodes


def call(primitive, targets, parameters, check=lambda: None):
    return BrokerCall("1" * 32, "2" * 32, primitive, tuple(targets), parameters,
                      DIGEST, "load", ("vm:read", "vm:power", "vm:console"), check)


def ids(vms, size):
    profile = vms.records.profile("node-0")
    return [f"libvirt-{profile['id']}-{index:032x}" for index in range(size)]


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_lifecycle_receipts_idempotence_reconciliation(tmp_path, monkeypatch, size):
    vms, provider, _, _ = setup(tmp_path, monkeypatch, size)
    selected = ids(vms, size)
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": selected}, lambda: None)
    assert len(preview["vms"]) == size
    operation = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    assert {item["state"] for item in operation["targets"]} == {"accepted"}
    again = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    assert again["id"] == operation["id"] and len(provider.calls) == size
    operation = await vms.operation("owner", operation["id"], lambda: None)
    assert {item["state"] for item in operation["targets"]} == {"observed"}
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "shutdown", "vm_ids": selected}, lambda: None)
    operation = await vms.commit("owner", preview["preview_id"], "idempotency-key-0002", lambda: None)
    assert len(provider.calls) == size * 2
    operation = await vms.operation("owner", operation["id"], lambda: None)
    assert {item["observed_state"] for item in operation["targets"]} == {"off"}
    validate_records(list(vms.service.store.db.execute("SELECT * FROM module_vm_profiles")),
                     list(vms.service.store.db.execute("SELECT * FROM module_vm_operations")), {"node-0"})


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_inventory_total_budget_and_per_node_refusal(tmp_path, monkeypatch, count):
    vms, _, denied, nodes = setup(tmp_path, monkeypatch, 64, count)
    result = await vms.broker("owner", call("vm.libvirt.list", list(nodes), {}), "instance")
    assert sum(len(item["data"]["results"]) for item in result) == min(count * 64, 256)
    assert len(vm_spec.encode(result)) < 1024 * 1024
    denied.add(("vm:read", f"node-{count - 1}"))
    result = await vms.broker("owner", call("vm.libvirt.list", list(nodes), {}), "instance")
    assert result[-1]["error"]["code"] == "denied"
    assert all("data" in item for item in result[:-1])


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_unknown_never_replayed_or_inferred_success(tmp_path, monkeypatch, size):
    vms, provider, _, _ = setup(tmp_path, monkeypatch, size)
    selected = ids(vms, size)
    previous = provider.apply

    def mixed(action, expected):
        provider.unknown = int(expected["uuid"], 16) % 2 == 0
        return previous(action, expected)

    provider.apply = mixed
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": selected}, lambda: None)
    operation = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    operation = await vms.operation("owner", operation["id"], lambda: None)
    assert {item["vm_id"]: item["state"] for item in operation["targets"]} == {
        target: "unknown" if index % 2 == 0 else "observed" for index, target in enumerate(selected)}
    assert {item["observed_state"] for item in operation["targets"]} == {"running"}
    closed = await vms.resolve("owner", operation["id"], selected[::2], lambda: None)
    assert {item["vm_id"]: item["state"] for item in closed["targets"]} == {
        target: "resolved" if index % 2 == 0 else "observed" for index, target in enumerate(selected)}
    again = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    assert again["id"] == operation["id"]
    assert provider.calls == [("start", f"{index:032x}") for index in range(size)]


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_accepted_without_effect_requires_explicit_resolution(tmp_path, monkeypatch, size):
    vms, provider, denied, _ = setup(tmp_path, monkeypatch, size)
    selected = ids(vms, size)

    def ignored(action, expected):
        provider.calls.append((action, expected["uuid"]))
        return {"state": "accepted"}
    monkeypatch.setattr(provider, "apply", ignored)
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": selected}, lambda: None)
    operation = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    observed = await vms.operation("owner", operation["id"], lambda: None)
    assert {item["state"] for item in observed["targets"]} == {"accepted"}
    assert {item["observed_state"] for item in observed["targets"]} == {"off"}
    again = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": selected}, lambda: None)
    with pytest.raises(Failure, match="unfinished"):
        await vms.commit("owner", again["preview_id"], "idempotency-key-0002", lambda: None)
    denied.add(("vm:read", "node-0"))
    with pytest.raises(Failure):
        await vms.resolve("owner", operation["id"], selected, lambda: None)
    assert {item["state"] for item in vms.records.get(operation["id"])["targets"]} == {"accepted"}
    denied.clear()
    calls = len(vms.service.ssh.calls)
    closed = await vms.resolve("owner", operation["id"], selected, lambda: None)
    assert {item["state"] for item in closed["targets"]} == {"resolved"}
    assert {item["observed_state"] for item in closed["targets"]} == {"off"}
    assert [request["action"] for request in vms.service.ssh.calls[calls:]] == ["status"]
    assert len(provider.calls) == size
    repeated = await vms.operation("owner", operation["id"], lambda: None)
    assert {item["state"] for item in repeated["targets"]} == {"resolved"}
    original = next(request for request in vms.service.ssh.calls if request["action"] == "apply")
    receipt = vm_rpc.dispatch(original | {"action": "receipt"})
    assert {item["state"] for item in receipt["results"]} == {"accepted"}


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_transport_loss_recovered_only_from_receipt(tmp_path, monkeypatch, size):
    vms, provider, _, _ = setup(tmp_path, monkeypatch, size)
    selected = ids(vms, size)
    vms.service.ssh.lose = True
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": selected}, lambda: None)
    for index in range(1, size, 2):
        provider.rows[f"{index:032x}"]["definition"] = "f" * 64
    operation = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    assert {item["vm_id"]: item["state"] for item in operation["targets"]} == dict.fromkeys(selected, "unknown")
    operation = await vms.operation("owner", operation["id"], lambda: None)
    assert {item["vm_id"]: item["state"] for item in operation["targets"]} == {
        target: "observed" if index % 2 == 0 else "refused" for index, target in enumerate(selected)}
    again = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    assert again["id"] == operation["id"]
    assert provider.calls == [("start", f"{index:032x}") for index in range(0, size, 2)]
    assert sum(item["action"] == "apply" for item in vms.service.ssh.calls) == 1


@pytest.mark.parametrize("change", ["node", "profile", "grant", "caller", "definition", "state"])
async def test_preview_revalidation(tmp_path, monkeypatch, change):
    vms, provider, denied, nodes = setup(tmp_path, monkeypatch)
    def check():
        pass
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": ids(vms, 1)}, check)
    if change == "node":
        nodes["node-0"]["host"] = "different.test"
    elif change == "profile":
        vms.set_profile("owner", "node-0", "session", False)
    elif change in {"grant", "caller"}:
        denied.add(("vm:power", "node-0"))
    else:
        provider.rows["0" * 32][change] = "b" * 64 if change == "definition" else "running"
    if change in {"definition", "state"}:
        operation = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", check)
        assert operation["targets"][0]["state"] == "refused"
    else:
        with pytest.raises(Failure):
            await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", check)
    assert not provider.calls


async def test_console_descriptor_never_uses_network_address(tmp_path, monkeypatch):
    vms, _, denied, _ = setup(tmp_path, monkeypatch)
    descriptor = await vms.console("owner", DIGEST, "instance", "node-0", ids(vms, 1)[0], lambda: None)
    argv, header = await vms.console_command(descriptor, lambda: None)
    assert "ficc_node.vm_console" in argv[-1]
    assert vm_spec.decode(header)["request"]["parameters"] == {"uuids": ["0" * 32]}
    assert "port" not in descriptor["graphics"] and "address" not in descriptor["graphics"]
    denied.add(("vm:console", "node-0"))
    with pytest.raises(Failure):
        await vms.console_command(descriptor, lambda: None)


async def test_module_cannot_commit_or_cross_profile_or_instance(tmp_path, monkeypatch):
    vms, _, _, _ = setup(tmp_path, monkeypatch)
    for primitive in ("vm.libvirt.commit", "vm.libvirt.resolve", "vm.libvirt.console"):
        with pytest.raises(Failure, match="not permitted"):
            await vms.broker("owner", call(primitive, ["node-0"], {}), "instance")
    with pytest.raises(Failure):
        await vms.broker("owner", call("vm.libvirt.status", ["node-0"], {"vm_ids": ["libvirt-" + "f" * 32 + "-" + "0" * 32]}), "instance")


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_cancel_after_dispatch_retains_unknown(tmp_path, monkeypatch, size):
    vms, provider, _, _ = setup(tmp_path, monkeypatch, size)
    selected = ids(vms, size)
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": selected}, lambda: None)
    entered = asyncio.Event()
    dispatches = []

    async def stall(node, command, payload, check, timeout):
        check()
        dispatches.append(vm_spec.decode(payload))
        entered.set()
        await asyncio.Event().wait()
    vms.service.ssh.command = stall
    task = asyncio.create_task(vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    operation = vms.records.all()[0]
    assert {item["vm_id"]: item["state"] for item in operation["targets"]} == dict.fromkeys(selected, "unknown")
    assert len(dispatches) == 1 and not provider.calls
    assert [item["uuid"] for item in dispatches[0]["parameters"]["intent"]["expected"]] == [
        f"{index:032x}" for index in range(size)]
    again = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    assert again["id"] == operation["id"] and len(dispatches) == 1
    assert not vms.inflight


def test_receipt_loss_and_changed_idempotent_intent(tmp_path, monkeypatch):
    _, provider, _, _ = setup(tmp_path, monkeypatch)
    request = {"version": 1, "action": "apply", "connection": "session", "profile": "a" * 32,
               "parameters": {"controller": "b" * 32, "operation": "c" * 32,
                              "intent": {"action": "start", "expected": [{key: provider.rows["0" * 32][key]
                                         for key in ("uuid", "state", "definition")}]}}}
    first = vm_state.receipt(provider, request)
    assert first == vm_state.receipt(provider, request) and len(provider.calls) == 1
    request["parameters"]["intent"]["action"] = "shutdown"
    with pytest.raises(ProviderError, match="different request"):
        vm_state.receipt(provider, request)


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_revocation_after_remote_effect_records_unknown(tmp_path, monkeypatch, size):
    vms, provider, denied, _ = setup(tmp_path, monkeypatch, size)
    selected = ids(vms, size)
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": selected}, lambda: None)
    previous = provider.apply

    def revoke(action, expected):
        result = previous(action, expected)
        denied.add(("vm:power", "node-0"))
        return result
    provider.apply = revoke
    with pytest.raises(Failure):
        await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    operation = vms.records.all()[0]
    assert {item["vm_id"]: item["state"] for item in operation["targets"]} == dict.fromkeys(selected, "unknown")
    assert provider.calls == [("start", f"{index:032x}") for index in range(size)]
    with pytest.raises(Failure):
        await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    assert sum(item["action"] == "apply" for item in vms.service.ssh.calls) == 1


async def test_backup_refuses_unfinished_and_tampered_intents(tmp_path, monkeypatch):
    vms, _, _, _ = setup(tmp_path, monkeypatch)
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": ids(vms, 1)}, lambda: None)
    operation = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    profiles = list(vms.service.store.db.execute("SELECT * FROM module_vm_profiles"))
    rows = list(vms.service.store.db.execute("SELECT * FROM module_vm_operations"))
    with pytest.raises(ValueError, match="unfinished"):
        validate_records(profiles, rows, {"node-0"})
    await vms.operation("owner", operation["id"], lambda: None)
    rows = [list(row) for row in vms.service.store.db.execute("SELECT * FROM module_vm_operations")]
    validate_records(profiles, rows, {"node-0"})
    data = vm_spec.decode(rows[0][-1].encode())
    data["targets"][0]["expected"]["definition"] = "f" * 64
    rows[0][-1] = vm_spec.encode(data).decode()
    with pytest.raises(ValueError, match="digest"):
        validate_records(profiles, rows, {"node-0"})


async def test_unknown_can_be_closed_after_profile_identity_changes(tmp_path, monkeypatch):
    vms, provider, _, nodes = setup(tmp_path, monkeypatch)
    provider.unknown = True
    preview = await vms.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "vm_ids": ids(vms, 1)}, lambda: None)
    operation = await vms.commit("owner", preview["preview_id"], "idempotency-key-0001", lambda: None)
    nodes["node-0"]["host"] = "changed.test"
    with pytest.raises(Failure, match="receipts"):
        vms.set_profile("owner", "node-0", "session")
    result = await vms.resolve("owner", operation["id"], ids(vms, 1), lambda: None)
    assert result["targets"][0]["state"] == "resolved"
    with pytest.raises(Failure, match="receipts"):
        vms.set_profile("owner", "node-0", "session")
