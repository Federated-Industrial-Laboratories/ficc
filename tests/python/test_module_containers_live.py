# SPDX-License-Identifier: Apache-2.0
"""Qualify real container APIs only on explicitly selected disposable fixtures."""

import asyncio
import importlib.util
import os
import secrets
from pathlib import Path

import pytest
from ficc_node import container_spec

from ficc.errors import Failure
from ficc.module_containers import Containers
from ficc.modules.archive import inspect_archive
from ficc.providers.containers import COMMAND
from ficc.service import Service
from ficc.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
ACCOUNTS = {"docker": "docktest", "podman": "podtest", "kubernetes": "kubetest"}


def package(service):
    spec = importlib.util.spec_from_file_location("container_package", ROOT / "tools/build-modules.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    manifest, files = builder.read_source(ROOT / "modules/containers")
    files["ficc_module.py"] = (ROOT / "sdk/python/ficc_module.py").read_bytes()
    archive = builder.build_archive(manifest, files)
    inspection = inspect_archive(archive)
    return service.modules.install(inspection, inspection.digest)["digest"]


@pytest.mark.parametrize("provider", ["docker", "podman", "kubernetes"])
async def test_disposable_container_inventory_logs_state_and_grants(tmp_path, provider):
    config = os.environ.get("FICC_CONTAINER_TEST_CONFIG")
    if not config or os.environ.get("FICC_REAL_MODULE_SANDBOX") != "1":
        pytest.skip("Set the disposable container SSH configuration and real sandbox opt-in.")
    alias = "ficc-" + ACCOUNTS[provider] + "-fixture"
    service = Service(Settings(state_dir=tmp_path / "state", ssh_config=Path(config), profiles=(alias,), control=False))
    host = Containers(service)
    dispatched = []
    original_command = service.ssh.command
    async def observed_command(node, command, payload=b"", check=None, timeout=10):
        if command == COMMAND:
            message = container_spec.decode(payload)
            if message["action"] == "apply":
                dispatched.append(message["parameters"]["operation"])
        return await original_command(node, command, payload, check=check, timeout=timeout)
    service.ssh.command = observed_command
    _, actor = service.auth.issue("token")
    original = None
    selection = None
    node = None
    digest = None
    try:
        sandbox = await service.module_runtime.sandbox.probe()
        assert sandbox.available, sandbox.reason
        preview = await service.ssh.preview(alias, "Disposable container fixture")
        assert preview["trust"] == "trusted"
        await service.ssh.install(preview)
        node = {**preview, "id": secrets.token_hex(16), "state": "ready", "last_seen": None,
                "capabilities": {}, "resources": None, "error": None}
        service.store.save_node(node)
        profile = await host.set_profile(actor.id, node["id"], provider, "context" if provider == "kubernetes" else "rootless",
            context="kind-ficc" if provider == "kubernetes" else "", namespace="ficc-fixture" if provider == "kubernetes" else "")
        print(f"PROVIDER {provider} VERSION {profile['version']} ACCOUNT_UID {profile['account_uid']}")
        digest = package(service)
        workspace = service.workspaces.create("Disposable containers")
        grants = [{"capability": "workspace:read", "target_ids": [workspace["id"]]},
                  {"capability": "container:read", "target_ids": [node["id"]]}]
        service.modules.set_enabled(digest, True, grants, sandbox_ready=sandbox.available)
        instance = secrets.token_hex(16)

        def check():
            service.authorize(actor.id, "modules:execute")
            service.modules.require(digest, "workspace:read", [workspace["id"]])

        async def invoke(action, parameters=None):
            return await service.module_runtime.invoke(digest, action, [node["id"]], parameters or {}, check,
                broker=lambda call: host.broker(actor.id, call, instance))

        async def rows():
            result = await invoke("load")
            data = result["results"][0]["data"]
            assert not data["notice"], data["notice"]
            return data["rows"]

        inventory = await rows()
        if provider == "kubernetes":
            selected = [row for row in inventory if row["values"]["kind"] == "deployment" and row["values"]["name"] == "fixture"]
            assert len(selected) == 1 and selected[0]["values"]["namespace"] == "ficc-fixture"
            selected_logs = [row for row in inventory if row["values"]["kind"] == "pod" and row["values"]["name"].startswith("fixture-")]
            assert selected_logs
            original = selected[0]["values"]["replicas"]
        else:
            assert {row["values"]["name"] for row in inventory} == {"fixture-a", "fixture-b"}
            selected = [row for row in inventory if row["values"]["name"] == "fixture-a"]
            selected_logs = selected
            original = selected[0]["values"]["state"]
            assert original in {"running", "exited", "stopped"}
        selection = selected[0]["id"]
        with pytest.raises(Failure):
            await invoke("logs", {"resource_ids": [selected_logs[0]["id"]]})
        full = grants + [{"capability": name, "target_ids": [node["id"]]} for name in ("container:logs", "container:power")]
        service.modules.set_enabled(digest, True, full, sandbox_ready=sandbox.available)
        logs = await invoke("logs", {"resource_ids": [selected_logs[0]["id"]]})
        assert logs["results"][0]["data"]["lines"]

        async def change(desired):
            action = "scale" if provider == "kubernetes" else "start" if desired == "running" else "stop"
            parameters = {"resource_ids": [selection]}
            if action == "scale":
                parameters["replicas"] = desired
            for attempt in range(5):
                result = await invoke("preview-" + action, parameters)
                frozen = host.preview_for_confirmation(actor.id, result["results"][0]["data"]["preview_id"], check)
                assert len(frozen["workloads"]) == 1
                key = secrets.token_hex(16)
                before = len(dispatched)
                operation = await host.commit(actor.id, frozen["preview_id"], key, check)
                if operation["targets"][0]["state"] != "refused":
                    break
                assert operation["targets"][0]["error"]["code"] == "container_stale"
                await asyncio.sleep(1)
            assert operation["targets"][0]["state"] in {"accepted", "unknown"}, operation
            assert (await host.commit(actor.id, frozen["preview_id"], key, check))["id"] == operation["id"]
            operation = await host.operation(actor.id, operation["id"], check)
            assert len(dispatched) == before + 1
            target = operation["targets"][0]
            assert target["resource_id"] == selection
            observed = target["observed"]
            assert observed["replicas"] == desired if provider == "kubernetes" else observed["state"] in ({"running"} if desired == "running" else {"exited", "stopped"})
            if target["state"] == "unknown":
                assert host.records.get(operation["id"])["targets"][0]["state"] == "unknown"
                operation = await host.resolve(actor.id, operation["id"], [selection], check)
                assert operation["targets"][0]["state"] == "resolved" and len(dispatched) == before + 1
                print(f"ACKNOWLEDGEMENT {provider} {action} UNKNOWN_INSPECTED_RESOLVED")
            else:
                assert target["state"] == "observed", operation
                print(f"ACKNOWLEDGEMENT {provider} {action} ACCEPTED_OBSERVED")
            return operation

        await change((0 if original else 1) if provider == "kubernetes" else "exited" if original == "running" else "running")
        await change(original)
        selection = None
        service.modules.set_enabled(digest, False, [])
        with pytest.raises(Failure):
            await invoke("load")
        service.modules.set_enabled(digest, True, grants, sandbox_ready=sandbox.available)
        final = await rows()
        row = next(row for row in final if row["id"] == selected[0]["id"])
        assert row["values"]["replicas" if provider == "kubernetes" else "state"] == original
        service.modules.set_enabled(digest, True, full, sandbox_ready=sandbox.available)
        for operation in host.records.all():
            assert await host.forget(actor.id, operation["id"], check) == {"removed": True}
        assert not host.records.all()
        assert await host.remove_profile(actor.id, profile["id"]) == {"removed": True}
        print(f"QUALIFIED {provider} INVENTORY {len(inventory)} RESTORED True")
    finally:
        try:
            if selection is not None and original is not None and node is not None and digest is not None:
                # Recovery uses the same fixed preview and commit authority as normal changes.
                for operation in host.records.all():
                    result = await host.operation(actor.id, operation["id"], lambda: None)
                    pending = [row["resource_id"] for row in result["targets"] if row["state"] in {"unknown", "accepted"}]
                    if pending:
                        await host.resolve(actor.id, operation["id"], pending, lambda: None)
                current = await host.transport.request(node, profile, "status", {"resources": [host.resources[selection]["resource"]]}, lambda: None)
                state = current["results"][0]["data"]
                value = state["replicas"] if provider == "kubernetes" else state["state"]
                if value != original:
                    await change(original)
        finally:
            await host.close()
            await service.module_runtime.stop()
            await service.ssh.close()
            service.close()
