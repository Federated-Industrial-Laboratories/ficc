# SPDX-License-Identifier: Apache-2.0
"""Verify power acknowledgements only on an explicitly isolated disposable guest."""

import asyncio
import json
import os
import secrets
import time
from pathlib import Path

import pytest
from ficc_node import admin_spec as spec
from test_module_admin_live import package

from ficc.module_admin import Administration
from ficc.modules.broker_protocol import BrokerCall
from ficc.providers.admin import COMMAND
from ficc.service import Service
from ficc.settings import Settings


async def test_disposable_reboot_poweroff_no_replay_and_inspected_resolution(tmp_path):
    config = os.environ.get("FICC_ADMIN_POWER_CONFIG")
    control = os.environ.get("FICC_ADMIN_POWER_CONTROL")
    expected_id = os.environ.get("FICC_ADMIN_POWER_ID")
    if not all((config, control, expected_id)) or os.environ.get("FICC_REAL_MODULE_SANDBOX") != "1":
        pytest.skip("Select the isolated power SSH fixture, identity, control program and real sandbox opt-in.")
    async def external(action):
        process = await asyncio.create_subprocess_exec(control, action, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        output, error = await asyncio.wait_for(process.communicate(), 150)
        assert process.returncode == 0, error[-1000:].decode(errors="replace")
        assert len(output) < 4096
        value = json.loads(output)
        assert value["id"] == expected_id and value["mode"] == "sealed"
        return value
    assert (await external("status"))["active"]
    alias = "ficc-admin-power-fixture"
    service = Service(Settings(state_dir=tmp_path / "state", ssh_config=Path(config), profiles=(alias,), control=False))
    host = Administration(service)
    _, actor = service.auth.issue("token")
    original = service.ssh.command
    dispatched = []
    async def record(node, command, payload=b"", check=None, timeout=10):
        if command == COMMAND and spec.decode(payload)["action"] == "apply":
            dispatched.append(spec.decode(payload)["parameters"]["operation"])
        return await original(node, command, payload, check=check, timeout=timeout)
    service.ssh.command = record
    try:
        sandbox = await service.module_runtime.sandbox.probe()
        assert sandbox.available, sandbox.reason
        preview = await service.ssh.preview(alias, "Disposable administration power fixture")
        assert preview["trust"] == "trusted" and preview["account"] == "root"
        code, raw, _ = await original(preview, "cat /etc/ficc-lab-disposable.json", b"", check=lambda: None, timeout=7)
        marker = json.loads(raw)
        assert code == 0 and marker == {"format": 1, "id": expected_id, "role": "admin-power"}
        await service.ssh.install(preview)
        node = {**preview, "id": secrets.token_hex(16), "state": "ready", "last_seen": None, "capabilities": {}, "resources": None, "error": None}
        service.store.save_node(node)
        profile = await host.set_profile(actor.id, node["id"], "system")
        assert profile["account_uid"] == 0
        digest = package(service)
        workspace = service.workspaces.create("Disposable power")
        grants = [{"capability": "workspace:read", "target_ids": [workspace["id"]]},
                  *[{"capability": cap, "target_ids": [node["id"]]} for cap in ("admin:read", "admin:power")]]
        service.modules.set_enabled(digest, True, grants, sandbox_ready=True)
        instance = secrets.token_hex(16)
        def check():
            service.modules.require(digest, "workspace:read", [workspace["id"]])
        async def invoke(action, params):
            return await service.module_runtime.invoke(digest, action, [node["id"]], params, check,
                broker=lambda call: host.broker(actor.id, call, instance))
        async def read():
            call = BrokerCall("1" * 32, "2" * 32, "admin.list", (node["id"],), {"kind": "system"}, digest,
                              "load", ("admin:read",), check)
            values = await host.broker(actor.id, call, instance)
            return values[0]["data"]["profiles"][0]["data"]["results"][0]
        async def boot_after(previous):
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                try:
                    row = await read()
                    if row["data"]["boot_id"] != previous and row["data"]["state"] == "running":
                        return row
                except Exception:
                    pass
                await asyncio.sleep(2)
            raise AssertionError("The isolated fixture did not reach running state with a new boot identity.")
        row = await read()
        identity = row["resource_id"]
        for action in ("reboot", "poweroff"):
            before_boot = row["data"]["boot_id"]
            result = await invoke("preview-" + action, {"resource_ids": [identity]})
            frozen = host.preview_for_confirmation(actor.id, result["results"][0]["data"]["preview_id"], check)
            key = secrets.token_hex(16)
            before = len(dispatched)
            operation = await host.commit(actor.id, frozen["preview_id"], key, check)
            assert {item["state"] for item in operation["targets"]} <= {"accepted", "unknown"}
            assert (await host.commit(actor.id, frozen["preview_id"], key, check))["id"] == operation["id"]
            if action == "poweroff":
                for _ in range(30):
                    if not (await external("status"))["active"]:
                        break
                    await asyncio.sleep(1)
                assert not (await external("status"))["active"]
                operation = await host.operation(actor.id, operation["id"], check)
                assert {item["state"] for item in operation["targets"]} <= {"accepted", "unknown"}
                await external("start")
            row = await boot_after(before_boot)
            assert row["resource_id"] == identity and row["data"]["boot_id"] != before_boot
            operation = await host.operation(actor.id, operation["id"], check)
            assert {item["state"] for item in operation["targets"]} <= {"accepted", "unknown"}
            assert len(dispatched) == before + 1
            operation = await host.resolve(actor.id, operation["id"], [identity], check)
            assert operation["targets"][0]["state"] == "resolved"
            assert await host.forget(actor.id, operation["id"], check) == {"removed": True}
            print(f"POWER {action} SAME IDENTITY; NEW BOOT; NO REPLAY; INSPECTED RESOLVED")
        assert not host.records.all()
        assert await host.remove_profile(actor.id, profile["id"]) == {"removed": True}
    finally:
        try:
            if not (await external("status"))["active"]:
                await external("start")
        finally:
            await host.close()
            await service.module_runtime.stop()
            await service.ssh.close()
            service.close()
