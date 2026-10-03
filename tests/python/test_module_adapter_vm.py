# SPDX-License-Identifier: Apache-2.0
"""Exercise complete adapter VM batches through grants, confirmation and recovery."""

import asyncio
import copy
from types import SimpleNamespace

import pytest
from test_module_adapters import host as host
from test_modules_packages import bundle, package
from test_modules_registry import registry as registry

from ficc.errors import Failure
from ficc.module_adapter_store import resource_id
from ficc.module_adapter_vm import AdapterVMs
from ficc.modules import inspect_archive
from ficc.modules.broker_protocol import BrokerCall


class Provider:
    def __init__(self, host, count):
        self.host, self.calls, self.cleaned = host, [], []
        self.rows = []
        self.wait = None
        self.entered = asyncio.Event()
        self.fail_apply = False
        self.task_pending = False
        self.fail_cleanup = False
        for index in range(count):
            key, birth = f"guest-{index}", f"{index + 1:064x}"
            resource = {"id": resource_id(key, birth), "key": key, "birth": birth, "revision": "c" * 64, "state": "off"}
            self.rows.append({"resource": resource, "name": key, "memory_kib": 65536, "vcpus": 1, "console": True})

    async def execute(self, selected, manifest, conversation, check):
        check()
        request = conversation.request
        phase, binding = request["phase"], request["bindings"][0]
        self.calls.append(copy.deepcopy(request))
        if phase == "probe":
            data = {"provider": {"name": "Test provider", "version": "1", "fingerprint": "b" * 64}}
        elif phase == "inventory":
            data = {"resources": copy.deepcopy(self.rows), "next_offset": None, "truncated": False}
        elif phase == "status":
            data = {"results": [{"id": resource["id"], "data": copy.deepcopy(next(row for row in self.rows
                                if row["resource"]["id"] == resource["id"]))} for resource in binding["resources"]]}
        elif phase == "prepare":
            data = {"results": [{"id": item["id"], "intent": {"key": item["key"]},
                "desired_state": "running"} for item in binding["resources"]]}
        else:
            if phase == "apply":
                self.entered.set()
                if self.wait is not None:
                    await self.wait.wait()
                check()
                if self.fail_apply:
                    raise Failure("lost", "The provider reply was lost.", 502)
            state = "accepted" if self.task_pending else "observed"
            data = {"results": [{"id": item["id"], "receipt": {"state": state,
                "token": {"task": item["key"]}, "completed": state == "observed",
                "result": "success" if state == "observed" else "unknown"}, "observed_state": "running"}
                for item in binding["resources"]]}
        check()
        return {"version": 1, "type": "adapter-result", "id": conversation.id,
                "results": [{"profile_id": selected["id"], "data": data}]}

    async def forget(self, selected, intent, outcomes, check):
        check()
        if self.fail_cleanup:
            raise Failure("offline", "The enrolled node is offline.", 502)
        self.cleaned.append((selected, intent, outcomes))


async def setup(host, count=1):
    provider = Provider(host, count)
    host.transport.execute = provider.execute
    host.transport.forget = provider.forget
    host.service.store.get_setting = lambda *_args: None
    host.service.store.set_setting = lambda *_args: None
    profile = await host.adapters.create("owner", host.digest, "linux-ssh", "d" * 32, "e" * 32)
    await host.adapters.grant("owner", profile["id"], 1, confirmed=True)
    profile = host.adapters.profile(profile["id"])
    inspection = inspect_archive(bundle(*package(id="org.example.vm-ui", capabilities=["vm:read", "vm:power", "vm:console"])))
    host.registry.install(inspection, inspection.digest)
    host.registry.set_enabled(inspection.digest, True, [{"capability": capability, "target_ids": ["d" * 32]}
        for capability in ("vm:read", "vm:power", "vm:console")], sandbox_ready=True)
    vms = AdapterVMs(host.service, host.adapters)
    def call(primitive, parameters):
        return BrokerCall("1" * 32, "2" * 32, primitive, ("d" * 32,), parameters, inspection.digest,
            "inspect", ("vm:read", "vm:power", "vm:console"), lambda: None)
    read = await vms.broker("owner", call("vm.adapter.list", {"profile_id": profile["id"]}), "3" * 32)
    ids = [row["vm_id"] for row in read[0]["data"]["results"]]
    parameters = {"profile_id": profile["id"], "vm_ids": ids, "action": "start"}
    preview = await vms.preview("owner", inspection.digest, "3" * 32, ["d" * 32], parameters, lambda: None)
    return SimpleNamespace(vms=vms, provider=provider, profile=profile, digest=inspection.digest,
                           preview=preview, ids=ids, parameters=parameters, call=call)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_complete_batch_has_frozen_consistency_and_no_replay(host, count):
    value = await setup(host, count)
    assert len(value.preview["vms"]) == count
    assert {row["consistency"] for row in value.preview["vms"]} == {"provider-lock"}
    committed = await value.vms.commit("owner", value.preview["preview_id"], "adapter-operation-key-0001", lambda: None)
    assert len(committed["targets"]) == count
    assert all(row["state"] == "observed" and row["profile_id"] == value.profile["id"] for row in committed["targets"])
    repeated = await value.vms.commit("owner", value.preview["preview_id"], "adapter-operation-key-0001", lambda: None)
    assert repeated["id"] == committed["id"]
    assert sum(call["phase"] == "apply" for call in value.provider.calls) == 1
    await host.adapters.revoke("owner", value.profile["id"])
    assert await value.vms.forget("owner", committed["id"], lambda: None) == {"removed": True, "orphaned_profiles": []}
    assert len(value.provider.cleaned) == 1
    await host.adapters.remove("owner", value.profile["id"])


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_unknown_cannot_replay_or_cleanup_and_explicit_resolution_retains_no_effect_claim(host, count):
    value = await setup(host, count)
    value.provider.fail_apply = True
    committed = await value.vms.commit("owner", value.preview["preview_id"], "adapter-operation-key-0001", lambda: None)
    assert all(row["state"] == "unknown" for row in committed["targets"])
    with pytest.raises(Failure, match="every outcome"):
        await value.vms.forget("owner", committed["id"], lambda: None)
    with pytest.raises(Failure, match="unfinished or unknown"):
        preview = await value.vms.preview("owner", value.digest, "3" * 32, ["d" * 32], value.parameters, lambda: None)
        await value.vms.commit("owner", preview["preview_id"], "adapter-operation-key-0002", lambda: None)
    resolved = await value.vms.resolve("owner", committed["id"], value.ids, lambda: None)
    assert all(row["state"] == "resolved" and "does not establish" in row["error"]["message"] for row in resolved["targets"])
    assert sum(call["phase"] == "apply" for call in value.provider.calls) == 1


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_known_active_provider_task_cannot_be_resolved(host, count):
    value = await setup(host, count)
    value.provider.task_pending = True
    committed = await value.vms.commit("owner", value.preview["preview_id"], "adapter-operation-key-0001", lambda: None)
    with pytest.raises(Failure, match="completed provider task"):
        await value.vms.resolve("owner", committed["id"], value.ids, lambda: None)
    value.provider.task_pending = False
    observed = await value.vms.operation("owner", committed["id"], lambda: None)
    assert all(row["state"] == "observed" for row in observed["targets"])


async def test_endpoint_change_requires_separate_orphan_ack_and_restore_revision_does_not(host):
    value = await setup(host)
    committed = await value.vms.commit("owner", value.preview["preview_id"], "adapter-operation-key-0001", lambda: None)
    await host.adapters.revoke("owner", value.profile["id"])
    host.transport.endpoint = lambda *_: {"id": "d" * 32, "revision": 2, "enabled": False, "machine_identity": "f" * 64}
    with pytest.raises(Failure) as caught:
        await value.vms.forget("owner", committed["id"], lambda: None)
    assert caught.value.code == "adapter_orphan_ack_required"
    assert "cleanup" not in value.vms.records.get(committed["id"])
    result = await value.vms.forget("owner", committed["id"], lambda: None, acknowledge_orphans=True)
    assert result["orphaned_profiles"] == [value.profile["id"]] and not value.provider.cleaned


async def test_transient_cleanup_failure_remains_retryable_after_restore_revision_change(host):
    value = await setup(host)
    committed = await value.vms.commit("owner", value.preview["preview_id"], "adapter-operation-key-0001", lambda: None)
    await host.adapters.revoke("owner", value.profile["id"])
    host.transport.revision = 2
    value.provider.fail_cleanup = True
    with pytest.raises(Failure) as caught:
        await value.vms.forget("owner", committed["id"], lambda: None, acknowledge_orphans=True)
    assert caught.value.code == "vm_cleanup_pending"
    assert value.vms.records.get(committed["id"])["cleanup"] == []
    value.provider.fail_cleanup = False
    assert (await value.vms.forget("owner", committed["id"], lambda: None))["removed"]


async def test_revoke_during_dispatch_retains_unknown_and_does_not_repeat(host):
    value = await setup(host)
    value.provider.wait = asyncio.Event()
    task = asyncio.create_task(value.vms.commit("owner", value.preview["preview_id"], "adapter-operation-key-0001", lambda: None))
    await value.provider.entered.wait()
    await host.adapters.revoke("owner", value.profile["id"])
    committed = await task
    assert committed["targets"][0]["state"] == "unknown"
    assert not value.vms.tasks and not host.adapters.active
    assert sum(call["phase"] == "apply" for call in value.provider.calls) == 1


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_acknowledged_method_without_job_can_close_after_current_state_read(host, count):
    value = await setup(host, count)
    value.provider.task_pending = True
    committed = await value.vms.commit("owner", value.preview["preview_id"], "adapter-operation-key-0001", lambda: None)
    record = value.vms.records.get(committed["id"])
    for target in record["targets"]:
        target["adapter_receipt"]["task_state"] = "none"
    value.vms.records.save(record)
    prior_reads = sum(call["phase"] == "status" for call in value.provider.calls)
    resolved = await value.vms.resolve("owner", committed["id"], value.ids, lambda: None)
    assert sum(call["phase"] == "status" for call in value.provider.calls) == prior_reads + 1
    assert all(item["state"] == "resolved" and item["observed_state"] == "off" for item in resolved["targets"])
    assert sum(call["phase"] == "apply" for call in value.provider.calls) == 1


async def test_unstamped_provider_resource_is_visible_but_power_is_refused(host):
    value = await setup(host)
    row = value.provider.rows[0]
    row["resource"]["birth"] = "0" * 64
    row["resource"]["id"] = resource_id(row["resource"]["key"], "0" * 64)
    call = value.call("vm.adapter.list", {"profile_id": value.profile["id"]})
    listed = await value.vms.broker("owner", call, "3" * 32)
    public = listed[0]["data"]["results"][0]
    assert not public["data"]["identity_ready"]
    with pytest.raises(Failure, match="documented identity setup"):
        await value.vms.preview("owner", value.digest, "3" * 32, ["d" * 32],
            {**value.parameters, "vm_ids": [public["vm_id"]]}, lambda: None)
    assert not any(call["phase"] == "apply" for call in value.provider.calls)


async def test_profile_choices_intersect_current_grants_identity_and_package_filter(host):
    value = await setup(host)
    call = value.call("vm.adapter.profiles", {})
    selected = await value.vms.broker("owner", call, "3" * 32)
    assert selected[0]["data"]["profiles"][0]["id"] == value.profile["id"]
    filtered = await value.vms.broker("owner", value.call("vm.adapter.profiles", {"adapter_id": "org.other.adapter"}), "3" * 32)
    assert filtered[0]["data"]["profiles"] == []
    host.transport.revision = 2
    assert (await value.vms.broker("owner", call, "3" * 32))[0]["data"]["profiles"] == []
    host.transport.revision = 1
    await host.adapters.revoke("owner", value.profile["id"])
    assert (await value.vms.broker("owner", call, "3" * 32))[0]["data"]["profiles"] == []
