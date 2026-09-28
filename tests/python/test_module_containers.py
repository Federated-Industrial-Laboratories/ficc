# SPDX-License-Identifier: Apache-2.0
"""Check bounded container grants, durable receipts and changed identities."""

import copy
import sqlite3
import threading
from types import SimpleNamespace

import pytest
from ficc_node import container_rpc, container_state
from ficc_node import container_spec as spec

from ficc.errors import Failure
from ficc.module_containers import Containers
from ficc.module_containers_store import retained, validate_records
from ficc.modules.broker_protocol import BrokerCall

DIGEST = "a" * 64


class Provider:
    def __init__(self, size):
        self.rows = {f"{i:064x}": {"resource": {"kind": "container", "id": f"{i:064x}", "name": f"fixture-{i}", "namespace": ""},
            "state": "exited", "revision": f"{i:064x}", "definition": "d" * 64, "image": "fixture",
            "replicas": None, "ready": None, "containers": []} for i in range(size)}
        self.calls, self.unknown, self.ignore = [], False, False

    def close(self):
        pass

    def probe(self):
        return {"binding": "b" * 64, "provider": "docker", "version": "29.0", "account_uid": 1000}

    def inventory(self, kind, offset, limit):
        rows = list(self.rows.values())[offset:offset + limit]
        more = offset + len(rows) < len(self.rows)
        return {"results": [{"resource": copy.deepcopy(row["resource"]), "data": copy.deepcopy(row)} for row in rows],
                "next_offset": offset + len(rows) if more else None, "truncated": more}

    def status(self, pointer):
        return copy.deepcopy(self.rows[pointer["id"]])

    def logs(self, pointer, tail, limit, container):
        return {"text": (pointer["name"] + "\n")[:limit], "truncated": False}

    def apply(self, action, expected, replicas):
        row = self.rows[expected["resource"]["id"]]
        if any(row[key] != expected[key] for key in expected):
            return {"state": "refused", "error": spec.error("container_stale", "Changed after preview.")}
        self.calls.append((action, row["resource"]["id"]))
        if not self.ignore:
            row["state"] = "running" if action == "start" else "exited"
            row["revision"] = spec.digest(row)
        return {"state": "unknown" if self.unknown else "accepted"}


async def setup(tmp_path, monkeypatch, size=1, count=1):
    nodes = {f"node-{i}": {"id": f"node-{i}", "profile": f"node-{i}", "host": "fixture.invalid", "account": "operator",
             "port": 22, "key_type": "ssh-ed25519", "key": "test"} for i in range(count)}
    denied = set()

    class Store:
        db = sqlite3.connect(":memory:")
        lock = threading.RLock()
        settings = {}

        def node(self, identity):
            return copy.deepcopy(nodes[identity])

        def get_setting(self, name, default):
            return self.settings.get(name, default)

        def set_setting(self, name, value):
            self.settings[name] = value

        def audit(self, *args, **kwargs):
            pass

    def authorize(actor, scope, target=None):
        if (scope, target) in denied:
            raise Failure("denied", "Caller scope denied.", 403)

    def require(digest, capability, targets):
        if digest != DIGEST or any((capability, target) in denied for target in targets):
            raise Failure("denied", "Module grant denied.", 403)

    provider = Provider(size)
    monkeypatch.setattr(container_rpc, "Engine", lambda value: provider)
    base = tmp_path / "receipts"
    base.mkdir(mode=0o700)
    monkeypatch.setattr(container_state, "root", lambda: base)

    class SSH:
        calls, lose = [], False

        async def command(self, node, command, payload, check, timeout):
            check()
            request = spec.decode(payload)
            self.calls.append(request)
            try:
                data = {"version": 1, "data": container_rpc.dispatch(request)}
            except spec.ProviderError as exc:
                data = {"version": 1, "error": spec.error(exc.code, exc.message)}
            if self.lose and request["action"] == "apply":
                raise Failure("disconnected", "Connection lost.", 502)
            check()
            return 0, spec.encode(data), b""

    service = SimpleNamespace(store=Store(), ssh=SSH(), authorize=authorize, modules=SimpleNamespace(require=require), live=lambda: None)
    host = Containers(service)
    for identity in nodes:
        await host.set_profile("owner", identity, "docker", "rootless")
    return host, provider, denied, nodes


def call(primitive, targets, parameters=None, check=lambda: None):
    return BrokerCall("1" * 32, "2" * 32, primitive, tuple(targets), parameters or {}, DIGEST, "action",
                     ("container:read", "container:logs", "container:power"), check)


async def inventory(host, nodes):
    return await host.broker("owner", call("container.list", nodes, {"limit": 256}), "instance")


def selected(host, size):
    profile = host.records.profiles()[0]
    return [spec.resource(profile["id"], {"kind": "container", "id": f"{i:064x}", "name": f"fixture-{i}", "namespace": ""}) for i in range(size)]


@pytest.mark.parametrize("size", [1, 64])
async def test_lifecycle_order_receipts_and_idempotence(tmp_path, monkeypatch, size):
    host, provider, _, _ = await setup(tmp_path, monkeypatch, size)
    await inventory(host, ["node-0"])
    ids = list(reversed(selected(host, size)))
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": ids}, lambda: None)
    assert [row["resource_id"] for row in preview["workloads"]] == ids
    result = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert {row["state"] for row in result["targets"]} == {"accepted"}
    again = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert again["id"] == result["id"] and len(provider.calls) == size
    assert retained(host.service.store, instance_id="instance")
    result = await host.operation("owner", result["id"], lambda: None)
    assert {row["state"] for row in result["targets"]} == {"observed"}
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "stop", "resource_ids": ids}, lambda: None)
    assert "10 seconds" in preview["effect"] and "forces" in preview["effect"]
    result = await host.commit("owner", preview["preview_id"], "test-idempotency-02", lambda: None)
    result = await host.operation("owner", result["id"], lambda: None)
    assert {row["observed"]["state"] for row in result["targets"]} == {"exited"}
    assert len(provider.calls) == size * 2 and not retained(host.service.store)
    validate_records(list(host.service.store.db.execute("SELECT * FROM module_container_profiles")),
                     list(host.service.store.db.execute("SELECT * FROM module_container_operations")), {"node-0"})


@pytest.mark.parametrize("count", [1, 64])
async def test_inventory_budget_status_logs_and_denied_profiles(tmp_path, monkeypatch, count):
    host, _, denied, nodes = await setup(tmp_path, monkeypatch, 64, count)
    rows = await inventory(host, nodes)
    assert [row["target"] for row in rows] == list(nodes)
    assert sum(len(profile["data"]["results"]) for row in rows for profile in row["data"]["profiles"]) == min(64 * count, 256)
    ids = [profile["data"]["results"][0]["resource_id"] for row in rows for profile in row["data"]["profiles"]]
    for primitive in ("status", "logs"):
        result = await host.broker("owner", call("container." + primitive, nodes, {"resource_ids": ids}), "instance")
        assert [row["target"] for row in result] == list(nodes)
        assert len(spec.encode(result)) < 1048576
    denied.add(("container:read", f"node-{count - 1}"))
    rows = await inventory(host, nodes)
    assert rows[-1]["data"]["profiles"][0]["error"]["code"] == "denied"


@pytest.mark.parametrize("lost,unknown", [(True, False), (False, True)])
async def test_lost_ack_reconciles_without_replay(tmp_path, monkeypatch, lost, unknown):
    host, provider, _, _ = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    provider.unknown, host.service.ssh.lose = unknown, lost
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": selected(host, 1)}, lambda: None)
    result = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert result["targets"][0]["state"] == "unknown"
    result = await host.operation("owner", result["id"], lambda: None)
    assert result["targets"][0]["state"] == ("unknown" if unknown else "observed")
    assert result["targets"][0]["observed"]["state"] == "running" and len(provider.calls) == 1
    if unknown:
        result = await host.resolve("owner", result["id"], selected(host, 1), lambda: None)
        assert result["targets"][0]["state"] == "resolved"


async def test_stale_preview_revoke_disabled_and_cross_instance(tmp_path, monkeypatch):
    host, provider, denied, nodes = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    ids = selected(host, 1)
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": ids}, lambda: None)
    denied.add(("container:power", "node-0"))
    with pytest.raises(Failure):
        await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert not provider.calls and not host.records.all()
    denied.clear()
    provider.rows["0" * 64]["revision"] = "f" * 64
    result = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert result["targets"][0]["state"] == "refused" and not provider.calls
    with pytest.raises(Failure):
        await host.broker("owner", call("container.operation", ["node-0"], {"operation_id": result["id"]}), "other-instance")
    profile = host.records.profiles()[0]
    await host.set_profile("owner", "node-0", "docker", "rootless", profile_id=profile["id"], enabled=False)
    with pytest.raises(Failure):
        host.groups(["node-0"], ids)
    await host.set_profile("owner", "node-0", "docker", "rootless", profile_id=profile["id"])
    nodes["node-0"]["key"] = "changed"
    with pytest.raises(Failure):
        host.groups(["node-0"], ids)


async def test_accepted_without_observed_effect_can_be_closed_explicitly(tmp_path, monkeypatch):
    host, provider, denied, _ = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    ids = selected(host, 1)
    provider.ignore = True
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": ids}, lambda: None)
    result = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    result = await host.operation("owner", result["id"], lambda: None)
    assert result["targets"][0]["state"] == "accepted"
    denied.add(("container:read", "node-0"))
    with pytest.raises(Failure):
        await host.resolve("owner", result["id"], ids, lambda: None)
    denied.clear()
    closed = await host.resolve("owner", result["id"], ids, lambda: None)
    assert closed["targets"][0]["state"] == "resolved" and len(provider.calls) == 1


async def test_controller_cancellation_retains_receipt_and_never_replays(tmp_path, monkeypatch):
    import asyncio
    host, provider, _, _ = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": selected(host, 1)}, lambda: None)
    original = host.service.ssh.command
    completed = asyncio.Event()
    async def paused(node, command, payload, **kwargs):
        result = await original(node, command, payload, **kwargs)
        if spec.decode(payload)["action"] == "apply":
            completed.set()
            await asyncio.Event().wait()
        return result
    monkeypatch.setattr(host.service.ssh, "command", paused)
    task = asyncio.create_task(host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None))
    await asyncio.wait_for(completed.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert host.dispatches and host.inflight
    await host.close()
    record = host.records.all()[0]
    assert record["targets"][0]["state"] == "unknown" and not host.inflight
    monkeypatch.setattr(host.service.ssh, "command", original)
    recovered = await host.operation("owner", record["id"], lambda: None)
    assert recovered["targets"][0]["state"] == "observed" and len(provider.calls) == 1
    with pytest.raises(Failure):
        await host.commit("owner", preview["preview_id"], "different-key-0001", lambda: None)


async def test_restore_validator_refuses_live_records_and_digest_tampering(tmp_path, monkeypatch):
    host, provider, _, _ = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    provider.unknown = True
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": selected(host, 1)}, lambda: None)
    result = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    profiles = list(host.service.store.db.execute("SELECT * FROM module_container_profiles"))
    operations = list(host.service.store.db.execute("SELECT * FROM module_container_operations"))
    validate_records(profiles, operations, {"node-0"}, quiescent=False)
    with pytest.raises(ValueError):
        validate_records(profiles, operations, {"node-0"})
    changed = [list(row) for row in operations]
    body = spec.decode(changed[0][4].encode())
    body["targets"][0]["expected"]["resource"]["name"] = "changed"
    changed[0][4] = spec.encode(body).decode()
    with pytest.raises(ValueError):
        validate_records(profiles, changed, {"node-0"}, quiescent=False)
    await host.resolve("owner", result["id"], selected(host, 1), lambda: None)
    operations = list(host.service.store.db.execute("SELECT * FROM module_container_operations"))
    validate_records([], operations, set())


@pytest.mark.parametrize("size", [1, 64])
async def test_terminal_history_removal_frees_node_and_controller_capacity(tmp_path, monkeypatch, size):
    host, provider, _, _ = await setup(tmp_path, monkeypatch, size)
    await inventory(host, ["node-0"])
    ids = selected(host, size)
    profile = host.records.profiles()[0]
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": ids}, lambda: None)
    operation = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    with pytest.raises(Failure):
        await host.forget("owner", operation["id"], lambda: None)
    with pytest.raises(Failure):
        await host.remove_profile("owner", profile["id"])
    await host.operation("owner", operation["id"], lambda: None)
    assert await host.forget("owner", operation["id"], lambda: None) == {"removed": True}
    assert not host.records.all() and not list((tmp_path / "receipts").glob("*.json"))
    assert len(provider.calls) == size
    assert await host.remove_profile("owner", profile["id"]) == {"removed": True}
    assert not host.records.profiles()


async def test_partial_history_cleanup_is_retained_and_retry_does_not_replay(tmp_path, monkeypatch):
    host, provider, _, nodes = await setup(tmp_path, monkeypatch, 2, 2)
    rows = await inventory(host, nodes)
    ids = [row["data"]["profiles"][0]["data"]["results"][index]["resource_id"] for index, row in enumerate(rows)]
    preview = await host.preview("owner", DIGEST, "instance", list(nodes), {"action": "start", "resource_ids": ids}, lambda: None)
    operation = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    await host.operation("owner", operation["id"], lambda: None)
    original, calls = host.service.ssh.command, []
    async def lost(node, command, payload, **kwargs):
        request = spec.decode(payload)
        result = await original(node, command, payload, **kwargs)
        if request["action"] == "forget":
            calls.append(request["profile"])
            if len(calls) == 2:
                raise Failure("lost", "The cleanup acknowledgement was lost.", 502)
        return result
    monkeypatch.setattr(host.service.ssh, "command", lost)
    with pytest.raises(Failure, match="Retry receipt removal"):
        await host.forget("owner", operation["id"], lambda: None)
    retained_record = host.records.get(operation["id"])
    assert len(retained_record["cleanup"]) == 1 and retained(host.service.store)
    with pytest.raises(ValueError):
        validate_records(list(host.service.store.db.execute("SELECT * FROM module_container_profiles")),
                         list(host.service.store.db.execute("SELECT * FROM module_container_operations")), set(nodes))
    assert not list((tmp_path / "receipts").glob("*.json"))
    restarted = Containers(host.service)
    assert await restarted.forget("owner", operation["id"], lambda: None) == {"removed": True}
    assert len(calls) == 3 and calls[1] == calls[2] and calls[0] != calls[2]
    assert len(provider.calls) == 2 and not host.records.all()


async def test_node_cleanup_requires_exact_terminal_proof(tmp_path, monkeypatch):
    host, provider, _, _ = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    provider.unknown = True
    ids = selected(host, 1)
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": ids}, lambda: None)
    operation = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    request = copy.deepcopy(host.service.ssh.calls[-1])
    request["action"] = "forget"
    request["parameters"]["outcomes"] = [{"resource": request["parameters"]["intent"]["expected"][0]["resource"], "state": "observed"}]
    with pytest.raises(spec.ProviderError, match="terminal outcome"):
        container_rpc.dispatch(request)
    assert list((tmp_path / "receipts").glob("*.json"))
    request["parameters"]["intent"]["expected"][0]["definition"] = "f" * 64
    with pytest.raises(spec.ProviderError, match="another request"):
        container_rpc.dispatch(request)
    await host.resolve("owner", operation["id"], ids, lambda: None)
    assert await host.forget("owner", operation["id"], lambda: None) == {"removed": True}


async def test_disconnected_http_waiter_leaves_owned_dispatch_running(tmp_path, monkeypatch):
    import asyncio
    host, provider, _, _ = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": selected(host, 1)}, lambda: None)
    original, completed, release = host.service.ssh.command, asyncio.Event(), asyncio.Event()
    async def paused(node, command, payload, **kwargs):
        result = await original(node, command, payload, **kwargs)
        if spec.decode(payload)["action"] == "apply":
            completed.set()
            await release.wait()
        return result
    monkeypatch.setattr(host.service.ssh, "command", paused)
    waiter = asyncio.create_task(host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None))
    await asyncio.wait_for(completed.wait(), 2)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    release.set()
    await asyncio.gather(*list(host.dispatches))
    record = host.records.all()[0]
    assert record["targets"][0]["state"] == "accepted" and len(provider.calls) == 1
    repeated = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert repeated["id"] == record["id"] and len(provider.calls) == 1


@pytest.mark.parametrize("count", [1, 64])
async def test_provider_filter_omits_other_registered_engines_without_false_errors(tmp_path, monkeypatch, count):
    host, _, _, nodes = await setup(tmp_path, monkeypatch, 1, count)
    result = await host.broker("owner", call("container.list", nodes, {"provider": "kubernetes"}), "instance")
    assert result == [{"target": node, "data": {"profiles": []}} for node in nodes]
    for profile in host.records.profiles():
        profile["enabled"] = False
        host.records.save_profile(profile)
    result = await host.broker("owner", call("container.list", nodes, {"provider": "all"}), "instance")
    assert all(row["error"]["code"] == "container_profile_missing" for row in result)
