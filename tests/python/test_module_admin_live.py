# SPDX-License-Identifier: Apache-2.0
"""Qualify administration only on explicitly selected disposable SSH fixtures."""

import asyncio
import importlib.util
import os
import secrets
from pathlib import Path

import pytest
from ficc_node import admin_spec as spec

from ficc.errors import Failure
from ficc.module_admin import Administration
from ficc.modules.archive import inspect_archive
from ficc.providers.admin import COMMAND
from ficc.service import Service
from ficc.settings import Settings

ROOT = Path(__file__).resolve().parents[2]


def package(service):
    module = importlib.util.spec_from_file_location("admin_package", ROOT / "tools/build-modules.py")
    builder = importlib.util.module_from_spec(module)
    module.loader.exec_module(builder)
    manifest, files = builder.read_source(ROOT / "modules/system-admin")
    files["ficc_module.py"] = (ROOT / "sdk/python/ficc_module.py").read_bytes()
    archive = builder.build_archive(manifest, files)
    inspection = inspect_archive(archive)
    return service.modules.install(inspection, inspection.digest)["digest"]


@pytest.mark.parametrize("size", [1, 64])
async def test_disposable_user_services_package_and_receipts(tmp_path, size):
    config = os.environ.get("FICC_ADMIN_TEST_CONFIG")
    if not config or os.environ.get("FICC_REAL_MODULE_SANDBOX") != "1":
        pytest.skip("Select the disposable administration SSH fixture and real sandbox opt-in.")
    alias = "ficc-admintest-fixture"
    service = Service(Settings(state_dir=tmp_path / "state", ssh_config=Path(config), profiles=(alias,), control=False))
    host = Administration(service)
    _, actor = service.auth.issue("token")
    dispatched, node = [], None
    command = service.ssh.command
    async def record(node, text, payload=b"", check=None, timeout=10):
        if text == COMMAND and spec.decode(payload)["action"] == "apply":
            dispatched.append(spec.decode(payload)["parameters"]["operation"])
        return await command(node, text, payload, check=check, timeout=timeout)
    service.ssh.command = record
    try:
        sandbox = await service.module_runtime.sandbox.probe()
        assert sandbox.available, sandbox.reason
        preview = await service.ssh.preview(alias, "Disposable administration fixture")
        assert preview["trust"] == "trusted" and preview["account"] == "admintest"
        await service.ssh.install(preview)
        node = {**preview, "id": secrets.token_hex(16), "state": "ready", "last_seen": None,
                "capabilities": {}, "resources": None, "error": None}
        service.store.save_node(node)
        profile = await host.set_profile(actor.id, node["id"], "user")
        assert profile["account_uid"] == 1104
        digest = package(service)
        workspace = service.workspaces.create("Disposable administration")
        grants = [{"capability": "workspace:read", "target_ids": [workspace["id"]]},
                  {"capability": "admin:read", "target_ids": [node["id"]]}]
        service.modules.set_enabled(digest, True, grants, sandbox_ready=True)
        instance = secrets.token_hex(16)
        def check():
            service.authorize(actor.id, "modules:execute")
            service.modules.require(digest, "workspace:read", [workspace["id"]])
        async def invoke(action, params=None):
            return await service.module_runtime.invoke(digest, action, [node["id"]], params or {}, check,
                broker=lambda call: host.broker(actor.id, call, instance))
        result = await invoke("load", {"kind": "service"})
        rows = result["results"][0]["data"]["rows"]
        chosen = [row for row in rows if row["values"]["name"] in {f"ficc-admin-test-{i:02d}.service" for i in range(size)}]
        assert len(chosen) == size, result
        assert all(row["values"]["state"] == "inactive" for row in chosen), chosen
        ids = [row["id"] for row in reversed(chosen)]
        with pytest.raises(Failure):
            await invoke("preview-start", {"resource_ids": ids})
        full = grants + [{"capability": cap, "target_ids": [node["id"]]} for cap in ("admin:services", "admin:logs")]
        service.modules.set_enabled(digest, True, full, sandbox_ready=True)
        for action in ("start", "restart", "stop"):
            result = await invoke("preview-" + action, {"resource_ids": ids})
            frozen = host.preview_for_confirmation(actor.id, result["results"][0]["data"]["preview_id"], check)
            assert [row["resource_id"] for row in frozen["resources"]] == ids
            before = len(dispatched)
            key = secrets.token_hex(16)
            operation = await host.commit(actor.id, frozen["preview_id"], key, check)
            assert {row["state"] for row in operation["targets"]} == {"accepted"}, operation
            assert (await host.commit(actor.id, frozen["preview_id"], key, check))["id"] == operation["id"]
            for _ in range(10):
                operation = await host.operation(actor.id, operation["id"], check)
                if {row["state"] for row in operation["targets"]} == {"observed"}:
                    break
                await asyncio.sleep(0.2)
            assert {row["state"] for row in operation["targets"]} == {"observed"}, operation
            assert len(dispatched) == before + 1
            if action == "start":
                logs = await invoke("logs", {"resource_ids": ids})
                assert any("started" in line for line in logs["results"][0]["data"]["lines"]), logs
            assert await host.forget(actor.id, operation["id"], check) == {"removed": True}
        service.modules.set_enabled(digest, False, [])
        with pytest.raises(Failure):
            await invoke("load")
        service.modules.set_enabled(digest, True, grants, sandbox_ready=True)
        with pytest.raises(Failure):
            await invoke("logs", {"resource_ids": ids})
        assert await host.remove_profile(actor.id, profile["id"]) == {"removed": True}
        assert not host.records.all()
        print(f"ADMIN SYSTEMD {profile['version']} UID 1104 N{size} START RESTART STOP OBSERVED; RECEIPTS REMOVED")
    finally:
        if node is not None:
            names = " ".join(f"ficc-admin-test-{i:02d}.service" for i in range(size))
            await command(node, "systemctl --user --no-ask-password stop -- " + names, b"", check=lambda: None, timeout=15)
        await host.close()
        await service.module_runtime.stop()
        await service.ssh.close()
        service.close()
