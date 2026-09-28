# SPDX-License-Identifier: Apache-2.0
"""Require explicit profile-bound provider authority before isolated adapter calls."""

import asyncio
from types import SimpleNamespace

import pytest
from test_module_adapter_manifest import adapter_package
from test_modules_packages import bundle
from test_modules_registry import registry as registry

from ficc.errors import Failure
from ficc.module_adapters import Adapters
from ficc.modules import inspect_archive
from ficc.modules import registry as registry_module
from ficc.modules.runtime import Runtime


class Transport:
    def __init__(self):
        self.revision = 1
        self.calls = []
        self.waiting = None
        self.entered = asyncio.Event()

    def endpoint(self, kind, endpoint_id):
        return {"id": endpoint_id, "revision": self.revision, "enabled": True, "machine_identity": "a" * 64}

    async def validate_binding(self, kind, endpoint_id, binding_id, check):
        check()

    async def qualify(self, selected, manifest, check):
        check()

    async def execute(self, selected, manifest, conversation, check):
        check()
        self.calls.append(conversation.request)
        self.entered.set()
        if self.waiting is not None:
            await self.waiting.wait()
        check()
        return {"version": 1, "type": "adapter-result", "id": conversation.id,
            "results": [{"profile_id": selected["id"], "data": {
                "provider": {"name": "Test provider", "version": "1", "fingerprint": "b" * 64}}}]}


@pytest.fixture
def host(registry, monkeypatch):
    monkeypatch.setattr(registry_module, "SUPPORTED", registry_module.SUPPORTED | {"provider:admin"})
    registry.store.audit = lambda *args, **kwargs: None
    calls = []
    service = SimpleNamespace(store=registry.store, modules=registry, live=lambda: None,
                              authorize=lambda *args: calls.append(args))
    transport = Transport()
    adapters = Adapters(service, transport=transport)
    inspection = inspect_archive(bundle(*adapter_package()))
    registry.install(inspection, inspection.digest)
    return SimpleNamespace(adapters=adapters, registry=registry, digest=inspection.digest,
                           transport=transport, authorized=calls, service=service)


@pytest.mark.parametrize("count", [1, 64])
async def test_only_explicit_qualified_profiles_receive_account_grants(host, count):
    profiles = []
    for index in range(count):
        endpoint = f"{index + 100:032x}"
        created = await host.adapters.create("owner", host.digest, "linux-ssh", endpoint, "c" * 32)
        assert not created["enabled"] and not created["admin_granted"]
        assert len(host.transport.calls) == index
        with pytest.raises(Failure, match="Confirm administration"):
            await host.adapters.grant("owner", created["id"], created["revision"])
        enabled = await host.adapters.grant("owner", created["id"], created["revision"], confirmed=True)
        assert enabled["enabled"] and enabled["admin_granted"] and enabled["ready"]
        assert enabled["consistency"] == "provider-lock"
        assert enabled["account_authority"] == "provider-administration"
        profiles.append(enabled)
    grant = host.registry.get(host.digest)["grants"]
    assert grant == [{"capability": "provider:admin", "target_ids": sorted(value["id"] for value in profiles)}]
    expected = {value["endpoint_id"] for value in profiles}
    assert {target for _actor, scope, target in host.authorized if scope == "providers:write"} == expected
    assert len(host.adapters.profiles("owner")) == count
    for value in profiles:
        await host.adapters.revoke("owner", value["id"])
    assert not host.registry.get(host.digest)["enabled"]


async def test_endpoint_change_invalidates_profile_and_never_transfers_grant(host):
    created = await host.adapters.create("owner", host.digest, "linux-ssh", "d" * 32, "c" * 32)
    await host.adapters.grant("owner", created["id"], 1, confirmed=True)
    host.transport.revision = 2
    stale = host.adapters.profiles("owner")[0]
    assert stale["enabled"] and stale["admin_granted"] and not stale["ready"]
    assert stale["diagnostic"]["code"] == "adapter_endpoint_changed"
    with pytest.raises(Failure, match="changed endpoint"):
        host.adapters.profile(created["id"])
    new = await host.adapters.create("owner", host.digest, "linux-ssh", "d" * 32, "c" * 32)
    assert new["id"] != created["id"] and not new["admin_granted"]
    await host.adapters.revoke("owner", created["id"])
    assert not host.registry.get(host.digest)["enabled"]


async def test_ordinary_module_invocation_cannot_run_an_enabled_adapter(host):
    created = await host.adapters.create("owner", host.digest, "linux-ssh", "d" * 32, "c" * 32)
    await host.adapters.grant("owner", created["id"], 1, confirmed=True)
    with pytest.raises(Failure, match="requires a host provider binding"):
        await Runtime(host.registry).invoke(host.digest, "probe", [created["id"]], {}, lambda: None)
    assert len(host.transport.calls) == 1 and not host.registry._leases


async def test_revoke_during_adapter_wait_cancels_and_releases_lease(host):
    created = await host.adapters.create("owner", host.digest, "linux-ssh", "d" * 32, "c" * 32)
    await host.adapters.grant("owner", created["id"], 1, confirmed=True)
    selected = host.adapters.profile(created["id"])
    host.transport.entered.clear()
    host.transport.waiting = asyncio.Event()
    task = asyncio.create_task(host.adapters.execute(selected, "inventory", "inventory", [], {}, lambda: None))
    await host.transport.entered.wait()
    await host.adapters.revoke("owner", created["id"])
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not host.adapters.active and not host.registry._leases


async def test_failed_probe_rolls_back_grant_and_profile_state(host):
    created = await host.adapters.create("owner", host.digest, "linux-ssh", "d" * 32, "c" * 32)
    async def fail(*args):
        raise Failure("unsupported", "The provider build is unavailable.", 409)
    host.transport.execute = fail
    with pytest.raises(Failure, match="provider build"):
        await host.adapters.grant("owner", created["id"], 1, confirmed=True)
    assert not host.registry.get(host.digest)["enabled"]
    assert not host.adapters.records.profile(created["id"])["enabled"]
    assert not host.registry._leases


async def test_caller_revocation_during_probe_cannot_enable_adapter(host):
    created = await host.adapters.create("owner", host.digest, "linux-ssh", "d" * 32, "c" * 32)
    host.transport.waiting = asyncio.Event()
    task = asyncio.create_task(host.adapters.grant("owner", created["id"], 1, confirmed=True))
    await host.transport.entered.wait()
    def denied(*args):
        raise Failure("denied", "The caller no longer has provider authority.", 403)
    host.service.authorize = denied
    host.transport.waiting.set()
    with pytest.raises(Failure, match="no longer"):
        await task
    assert not host.registry.get(host.digest)["enabled"]


async def test_retained_previous_version_blocks_implicit_package_switch(host):
    created = await host.adapters.create("owner", host.digest, "linux-ssh", "d" * 32, "c" * 32)
    await host.adapters.grant("owner", created["id"], 1, confirmed=True)
    inspection = inspect_archive(bundle(*adapter_package(version="2.0.0")))
    host.registry.install(inspection, inspection.digest)
    new = await host.adapters.create("owner", inspection.digest, "linux-ssh", "d" * 32, "c" * 32)
    with pytest.raises(Failure, match="prior adapter profiles"):
        await host.adapters.grant("owner", new["id"], 1, confirmed=True)
    assert host.registry.get(host.digest)["enabled"] and not host.registry.get(inspection.digest)["enabled"]
