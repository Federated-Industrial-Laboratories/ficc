# SPDX-License-Identifier: Apache-2.0
"""Check bounded admin grants, durable receipts and changed identities."""

import copy
import sqlite3
import threading
from types import SimpleNamespace

import pytest
from ficc_node import admin_rpc, admin_state
from ficc_node import admin_spec as spec

from ficc.errors import Failure
from ficc.module_admin import Administration
from ficc.module_admin_store import retained, validate_records
from ficc.modules.broker_protocol import BrokerCall

DIGEST = "a" * 64


class Provider:
    def __init__(self, size):
        self.rows = {f"{i:064x}": {"resource": {"kind": "service", "id": f"{i:064x}", "name": f"fixture-{i}.service"},
            "state": "inactive", "revision": f"{i:064x}", "definition": "d" * 64, "boot_id": "b" * 32, "invocation": "", "detail": "dead", "metrics": None} for i in range(size)}
        self.calls, self.unknown, self.ignore = [], False, False

    def close(self):
        pass

    def probe(self):
        return {"binding": "b" * 64, "provider": "systemd", "version": "259", "account_uid": 1000, "system_id": "c" * 64}

    def inventory(self, kind, offset, limit):
        rows = list(self.rows.values())[offset:offset + limit]
        more = offset + len(rows) < len(self.rows)
        return {"results": [{"resource": copy.deepcopy(row["resource"]), "data": copy.deepcopy(row)} for row in rows],
                "next_offset": offset + len(rows) if more else None, "truncated": more}

    def status(self, pointer):
        return copy.deepcopy(self.rows[pointer["id"]])

    def status_batch(self, pointers):
        return {"results": [{"resource": item, "data": self.status(item)} for item in pointers]}

    def logs(self, pointer, tail, limit):
        return {"text": (pointer["name"] + "\n")[:limit], "truncated": False}

    def apply_batch(self, action, expected):
        return [{"resource": item["resource"], **self.apply(action, item)} for item in expected]

    def apply(self, action, expected):
        row = self.rows[expected["resource"]["id"]]
        if any(row[key] != expected[key] for key in expected):
            return {"state": "refused", "error": spec.error("admin_stale", "Changed after preview.")}
        self.calls.append((action, row["resource"]["id"]))
        if not self.ignore:
            row["state"] = "active" if action in {"start", "restart"} else "inactive"
            row["invocation"] = f"{len(self.calls):032x}"
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
    monkeypatch.setattr(admin_rpc, "Systemd", lambda value: provider)
    base = tmp_path / "receipts"
    base.mkdir(mode=0o700)
    monkeypatch.setattr(admin_state, "root", lambda: base)

    class SSH:
        calls, lose = [], False

        async def command(self, node, command, payload, check, timeout):
            check()
            request = spec.decode(payload)
            self.calls.append(request)
            try:
                data = {"version": 1, "data": admin_rpc.dispatch(request)}
            except spec.ProviderError as exc:
                data = {"version": 1, "error": spec.error(exc.code, exc.message)}
            if self.lose and request["action"] == "apply":
                raise Failure("disconnected", "Connection lost.", 502)
            check()
            return 0, spec.encode(data), b""

    service = SimpleNamespace(store=Store(), ssh=SSH(), authorize=authorize, modules=SimpleNamespace(require=require), live=lambda: None)
    host = Administration(service)
    for identity in nodes:
        await host.set_profile("owner", identity, "user")
    return host, provider, denied, nodes


def call(primitive, targets, parameters=None, check=lambda: None):
    return BrokerCall("1" * 32, "2" * 32, primitive, tuple(targets), parameters or {}, DIGEST, "action",
                     ("admin:read", "admin:logs", "admin:services", "admin:power"), check)


async def inventory(host, nodes):
    return await host.broker("owner", call("admin.list", nodes, {"limit": 256}), "instance")


def selected(host, size):
    profile = host.records.profiles()[0]
    return [spec.resource(profile["id"], {"kind": "service", "id": f"{i:064x}", "name": f"fixture-{i}.service"}) for i in range(size)]


@pytest.mark.parametrize("size", [1, 64])
async def test_lifecycle_order_receipts_and_idempotence(tmp_path, monkeypatch, size):
    host, provider, _, _ = await setup(tmp_path, monkeypatch, size)
    await inventory(host, ["node-0"])
    ids = list(reversed(selected(host, size)))
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": ids}, lambda: None)
    assert [row["resource_id"] for row in preview["resources"]] == ids
    result = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert {row["state"] for row in result["targets"]} == {"accepted"}
    again = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert again["id"] == result["id"] and len(provider.calls) == size
    assert retained(host.service.store, instance_id="instance")
    result = await host.operation("owner", result["id"], lambda: None)
    assert {row["state"] for row in result["targets"]} == {"observed"}
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "stop", "resource_ids": ids}, lambda: None)
    assert "stop timeouts" in preview["effect"] and "not an atomic" in preview["effect"]
    result = await host.commit("owner", preview["preview_id"], "test-idempotency-02", lambda: None)
    result = await host.operation("owner", result["id"], lambda: None)
    assert {row["observed"]["state"] for row in result["targets"]} == {"inactive"}
    assert len(provider.calls) == size * 2 and not retained(host.service.store)
    validate_records(list(host.service.store.db.execute("SELECT * FROM module_admin_profiles")),
                     list(host.service.store.db.execute("SELECT * FROM module_admin_operations")), {"node-0"})


@pytest.mark.parametrize("count", [1, 64])
async def test_inventory_budget_status_logs_and_denied_profiles(tmp_path, monkeypatch, count):
    host, _, denied, nodes = await setup(tmp_path, monkeypatch, 64, count)
    rows = await inventory(host, nodes)
    assert [row["target"] for row in rows] == list(nodes)
    assert sum(len(profile["data"]["results"]) for row in rows for profile in row["data"]["profiles"]) == min(64 * count, 256)
    ids = [profile["data"]["results"][0]["resource_id"] for row in rows for profile in row["data"]["profiles"]]
    for primitive in ("status", "logs"):
        result = await host.broker("owner", call("admin." + primitive, nodes, {"resource_ids": ids}), "instance")
        assert [row["target"] for row in result] == list(nodes)
        assert len(spec.encode(result)) < 1048576
    denied.add(("admin:read", f"node-{count - 1}"))
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
    assert result["targets"][0]["observed"]["state"] == "active" and len(provider.calls) == 1
    if unknown:
        result = await host.resolve("owner", result["id"], selected(host, 1), lambda: None)
        assert result["targets"][0]["state"] == "resolved"


async def test_stale_preview_revoke_disabled_and_cross_instance(tmp_path, monkeypatch):
    host, provider, denied, nodes = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    ids = selected(host, 1)
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": ids}, lambda: None)
    denied.add(("admin:services", "node-0"))
    with pytest.raises(Failure):
        await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert not provider.calls and not host.records.all()
    denied.clear()
    provider.rows["0" * 64]["revision"] = "f" * 64
    result = await host.commit("owner", preview["preview_id"], "test-idempotency-01", lambda: None)
    assert result["targets"][0]["state"] == "refused" and not provider.calls
    with pytest.raises(Failure):
        await host.broker("owner", call("admin.operation", ["node-0"], {"operation_id": result["id"]}), "other-instance")
    profile = host.records.profiles()[0]
    await host.set_profile("owner", "node-0", "user", profile_id=profile["id"], enabled=False)
    with pytest.raises(Failure):
        host.groups(["node-0"], ids)
    await host.set_profile("owner", "node-0", "user", profile_id=profile["id"])
    nodes["node-0"]["key"] = "changed"
    with pytest.raises(Failure):
        host.groups(["node-0"], ids)



@pytest.mark.parametrize("action", ["reboot", "poweroff"])
@pytest.mark.parametrize("count", [1, 64])
async def test_power_acknowledgement_never_proves_completion(tmp_path, monkeypatch, action, count):
    host, provider, _, nodes = await setup(tmp_path, monkeypatch, count=count)
    profiles = host.records.profiles()
    for index, profile in enumerate(profiles):
        profile.update(manager="system", system_id=f"{index:064x}", binding=f"{index:064x}")
        host.records.save_profile(profile)
    row = next(iter(provider.rows.values()))
    row["resource"].update(kind="system", name="system")
    row["state"] = "running"
    row["power"] = dict.fromkeys(spec.POWER, "yes")
    provider.ignore = True
    await inventory(host, nodes)
    identities = [spec.resource(profile["id"], row["resource"]) for profile in reversed(profiles)]
    if count > 1:
        duplicate = {**profiles[-1], "system_id": profiles[0]["system_id"]}
        host.records.save_profile(duplicate)
        with pytest.raises(Failure, match="each physical system once"):
            await host.preview("owner", DIGEST, "instance", list(nodes), {"action": action, "resource_ids": identities}, lambda: None)
        assert not host.previews and not provider.calls
        host.records.save_profile(profiles[-1])
    preview = await host.preview("owner", DIGEST, "instance", list(nodes), {"action": action, "resource_ids": identities}, lambda: None)
    assert "queued, not complete" in preview["effect"]
    assert [item["resource_id"] for item in preview["resources"]] == identities
    operation = await host.commit("owner", preview["preview_id"], "power-idempotency-01", lambda: None)
    assert {item["state"] for item in operation["targets"]} == {"accepted"}
    assert (await host.commit("owner", preview["preview_id"], "power-idempotency-01", lambda: None))["id"] == operation["id"]
    row["boot_id"] = "c" * 32
    operation = await host.operation("owner", operation["id"], lambda: None)
    assert {item["state"] for item in operation["targets"]} == {"accepted"}
    assert len(provider.calls) == count
    with pytest.raises(ValueError, match="Resolve"):
        validate_records(list(host.service.store.db.execute("SELECT * FROM module_admin_profiles")),
                         list(host.service.store.db.execute("SELECT * FROM module_admin_operations")), set(nodes))
    operation = await host.resolve("owner", operation["id"], identities, lambda: None)
    assert {item["state"] for item in operation["targets"]} == {"resolved"}
    assert "does not establish" in operation["targets"][0]["error"]["message"]
    assert await host.forget("owner", operation["id"], lambda: None) == {"removed": True}
    assert not host.records.all()


async def test_action_capabilities_are_separate_and_read_is_required(tmp_path, monkeypatch):
    from dataclasses import replace
    host, _, _, _ = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    value = call("admin.preview", ["node-0"], {"action": "start", "resource_ids": selected(host, 1)})
    for capabilities in [("admin:read", "admin:power"), ("admin:services",)]:
        with pytest.raises(Failure, match="primitive"):
            await host.broker("owner", replace(value, action_capabilities=capabilities), "instance")
    assert not host.previews


async def test_receipt_cleanup_retries_without_replay_and_blocks_profile_change(tmp_path, monkeypatch):
    host, provider, _, _ = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": selected(host, 1)}, lambda: None)
    operation = await host.commit("owner", preview["preview_id"], "cleanup-idempotency-1", lambda: None)
    operation = await host.operation("owner", operation["id"], lambda: None)
    profile = host.records.profiles()[0]
    with pytest.raises(Failure):
        await host.remove_profile("owner", profile["id"])
    command = host.service.ssh.command
    failed = False
    async def lose_cleanup(node, command_text, payload, check, timeout):
        nonlocal failed
        result = await command(node, command_text, payload, check, timeout)
        if spec.decode(payload)["action"] == "forget" and not failed:
            failed = True
            raise Failure("lost", "The cleanup acknowledgement was lost.", 502)
        return result
    host.service.ssh.command = lose_cleanup
    with pytest.raises(Failure, match="Retry receipt"):
        await host.forget("owner", operation["id"], lambda: None)
    assert host.records.get(operation["id"])["cleanup"] == []
    assert await host.forget("owner", operation["id"], lambda: None) == {"removed": True}
    assert len(provider.calls) == 1
    assert await host.remove_profile("owner", profile["id"]) == {"removed": True}


async def test_client_disconnect_does_not_cancel_durable_dispatch(tmp_path, monkeypatch):
    import asyncio
    host, provider, _, _ = await setup(tmp_path, monkeypatch)
    await inventory(host, ["node-0"])
    preview = await host.preview("owner", DIGEST, "instance", ["node-0"], {"action": "start", "resource_ids": selected(host, 1)}, lambda: None)
    command = host.service.ssh.command
    entered, release = asyncio.Event(), asyncio.Event()
    async def delayed(node, command_text, payload, check, timeout):
        if spec.decode(payload)["action"] == "apply":
            entered.set()
            await release.wait()
        return await command(node, command_text, payload, check, timeout)
    host.service.ssh.command = delayed
    task = asyncio.create_task(host.commit("owner", preview["preview_id"], "cancel-idempotency-1", lambda: None))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await asyncio.gather(*list(host.dispatches))
    result = await host.commit("owner", preview["preview_id"], "cancel-idempotency-1", lambda: None)
    assert result["targets"][0]["state"] == "accepted" and len(provider.calls) == 1


@pytest.mark.parametrize("parameters", [{}, {"action": "force"}, {"action": []}])
async def test_malformed_action_is_a_bounded_broker_error(tmp_path, monkeypatch, parameters):
    host, provider, _, _ = await setup(tmp_path, monkeypatch)
    with pytest.raises(Failure) as caught:
        await host.broker("owner", call("admin.preview", ["node-0"], parameters), "instance")
    assert caught.value.code == "admin_invalid" and not provider.calls and not host.records.all()
