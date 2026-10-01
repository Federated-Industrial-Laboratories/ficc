# SPDX-License-Identifier: Apache-2.0
"""Qualify installed VirtualBox packages through real host grants and receipts."""

import asyncio
import copy
import hashlib
import json
import os
import secrets
import struct
import time
from functools import partial
from pathlib import Path

import pytest
from test_module_virtualbox_live_support import checked
from test_module_virtualbox_live_support import live_vbox as live_vbox

from ficc.errors import Failure
from ficc.providers.adapter_transport import COMMAND
from ficc.viewer.wire import instruction, parse
from ficc.viewer_stream import bridge


def display(live, selected):
    opened = live.invoke("open-console", {"vm_ids": [selected]})
    public = opened["results"][0]["data"]
    assert set(public) == {"viewer_ref"}
    reference = public["viewer_ref"]
    ticket = checked(live.client.post(f"/api/v1/viewers/{reference}/tickets"))
    assert set(ticket) == {"ticket", "expires_in", "audio", "vm_id", "system"}
    assert ticket["audio"] is False
    current = live.service.viewers.current(reference, live.actor)
    descriptor = current["descriptor"]
    graphics = descriptor["graphics"]
    assert graphics["authentication"] == "rfb-password" and graphics["audio"] is False
    assert "password" not in graphics

    def guard():
        live.service.viewers.current(reference, live.actor)

    class Complete(Exception):
        pass

    async def run():
        queue = asyncio.Queue()
        counts = {"image": 0, "end": 0, "size": 0, "sync": 0}
        class Socket:
            async def send_bytes(self, data):
                value = parse(data.decode(), 65536)
                if value[0] in counts:
                    counts[value[0]] += 1
                if value[0] == "img" and value[3] == "0":
                    counts["image"] += 1
                await queue.put(json.dumps({"type": "ack", "bytes": len(data)}))
                if value[0] == "sync":
                    if all(counts.values()):
                        raise Complete()
                    await queue.put(json.dumps({"type": "input", "instruction": instruction("sync", value[1]).decode()}))
            async def receive_text(self):
                return await queue.get()
        arguments, header = await live.service.adapter_vms.console_command(descriptor, guard)
        with pytest.raises(Complete):
            async with asyncio.timeout(60):
                await bridge(Socket(), Path(os.environ["FICC_VIEWER_RUNTIME"]), arguments, header, guard,
                             authentication=graphics["authentication"])
    live.client.portal.call(run)
    return descriptor, guard


def test_live_readonly_confirmed_power_no_replay_console_revoke(live_vbox, monkeypatch):
    live = live_vbox
    if not os.environ.get("FICC_VIEWER_RUNTIME"):
        pytest.skip("A qualified native display runtime is required.")
    choices = live.invoke("profiles")["results"][0]["data"]["profiles"]
    assert [value["id"] for value in choices] == [live.profile["id"]]
    rows = live.fixture_rows()
    assert rows[live.fixture["vm_name"]]["values"]["state"] == "off"
    selected = rows[live.fixture["vm_name"]]["id"]
    live.invoke("preview-start", {"vm_ids": [selected]}, status=403)
    live.invoke("open-console", {"vm_ids": [selected]}, status=403)
    grants = live.grants + [{"capability": name, "target_ids": [live.node["id"]]} for name in ("vm:power", "vm:console")]
    live.activate(grants)
    previous = live.service.ssh.command
    dispatched = []
    async def monitor(node, command, payload=b"", check=None, timeout=10):
        if command == COMMAND:
            size = struct.unpack(">I", payload[:4])[0]
            request = json.loads(payload[4:4 + size])
            if request["action"] == "execute" and request["parameters"]["request"]["phase"] == "apply":
                dispatched.append(request["parameters"]["request"])
        return await previous(node, command, payload, check=check, timeout=timeout)
    monkeypatch.setattr(live.service.ssh, "command", monitor)
    preview = live.preview("start", selected)
    live.activate(live.grants)
    live.commit(preview, status=403)
    assert not dispatched
    live.activate(grants)
    boot_nonce = secrets.token_hex(16)
    assert live.boot("arm", boot_nonce) == {"armed": True}
    preview = live.preview("start", selected)
    checked(live.client.post("/api/v1/module-vms/commit", json={**live.context,
        "preview_id": preview["preview_id"], "confirm": False}, headers={"Idempotency-Key": secrets.token_hex(16)}), 422)
    assert not dispatched
    key = secrets.token_hex(16)
    started = live.commit(preview, key)
    assert started["targets"][0]["state"] == "accepted"
    assert live.commit(preview, key)["id"] == started["id"] and len(dispatched) == 1
    observed = live.wait_operation(started["id"])
    assert observed["targets"][0]["state"] == "observed" and observed["targets"][0]["observed_state"] == "running"
    live.wait_boot(boot_nonce)
    live.inventory()
    descriptor, guard = display(live, selected)
    live.activate(live.grants)
    with pytest.raises(Failure):
        live.client.portal.call(live.service.adapter_vms.console_command, descriptor, guard)
    live.activate(grants)
    # A rendered boot framebuffer does not establish guest ACPI readiness.
    deadline = time.monotonic() + 180
    while True:
        response = live.client.post("/api/v1/module-invocations", json={**live.context, "targets": [live.node["id"]],
            "action": "preview-shutdown", "parameters": {"profile_id": live.profile["id"], "vm_ids": [selected]}})
        if response.status_code == 200:
            prepared = response.json()["results"][0]["data"]
            break
        assert response.status_code == 409 and "ACPI" in response.text, response.text[:2048]
        assert time.monotonic() < deadline, "The guest did not enter ACPI mode."
        time.sleep(3)
    preview = checked(live.client.post("/api/v1/module-vms/preview", json={**live.context, "preview_id": prepared["preview_id"]}))
    shutdown = live.commit(preview)
    observed = live.wait_operation(shutdown["id"], timeout=180)
    assert observed["targets"][0]["observed_state"] == "off" and len(dispatched) == 2
    assert live.forget(started)["removed"] and live.forget(shutdown)["removed"]
    checked(live.client.post(f"/api/v1/adapter-profiles/{live.profile['id']}/revoke"))
    assert live.invoke("profiles")["results"][0]["data"]["profiles"] == []


def test_live_inventory_status_prepare_and_stale_receipts64(live_vbox):
    prefix = os.environ.get("FICC_VBOX_TEST_BATCH")
    if not prefix:
        pytest.skip("An explicit owned, powered-off 64-definition fixture batch is required.")
    live = live_vbox
    assert prefix == live.fixture["batch_prefix"]
    first, second = live.inventory(), live.inventory(64)
    assert len(first["rows"]) == 64 and "offset 64" in first["notice"]
    assert len(second["rows"]) == 1 and not second["notice"]
    rows = [row for row in first["rows"] + second["rows"] if row["values"]["name"].startswith(prefix + "-")]
    assert len(rows) == 64 and len({row["id"] for row in rows}) == 64
    assert {row["values"]["state"] for row in rows} == {"off"}
    host = live.service.adapter_vms
    profiles, grouped = host.groups([live.node["id"]], [row["id"] for row in rows])
    profile = profiles[live.profile["id"]]
    resources = grouped[profile["id"]]
    guard = host.guard(live.actor, live.digest, live.node["id"], "vm:read", profile, lambda: None)
    execute = live.service.adapters.execute
    status = live.client.portal.call(execute, profile, "status", "status", resources, {}, guard)
    assert len(status["results"]) == 64 and all("data" in row for row in status["results"])
    live.activate(live.grants + [{"capability": "vm:power", "target_ids": [live.node["id"]]}])
    preview = live.invoke("preview-start", {"vm_ids": [row["id"] for row in rows]})["results"][0]["data"]
    assert len(preview["vms"]) == 64
    assert {row["consistency"] for row in preview["vms"]} == {"checked-before-dispatch"}
    # Exercise actual package refusal and node journal semantics without starting
    # 64 guests: every frozen revision is deliberately stale before dispatch.
    stale = copy.deepcopy(resources)
    for resource in stale:
        resource["revision"] = "0" * 64
    intent = {"controller": secrets.token_hex(16), "operation": secrets.token_hex(16),
        "digest": hashlib.sha256(json.dumps(stale, sort_keys=True).encode()).hexdigest(),
        "targets": [{"id": resource["id"], "intent": {"resource": resource, "action": "start", "method": "LaunchVMProcess"}}
                    for resource in stale]}
    guard = host.guard(live.actor, live.digest, live.node["id"], "vm:power", profile, lambda: None)
    call = partial(execute, profile, "apply", "start", stale, {}, guard, intent=intent)
    result = live.client.portal.call(call)
    assert len(result["results"]) == 64 and {row["receipt"]["state"] for row in result["results"]} == {"refused"}
    assert live.client.portal.call(call) == result
    live.client.portal.call(live.service.adapters.transport.forget, profile, intent,
        [{"id": resource["id"], "state": "refused"} for resource in stale], guard)
    current = live.client.portal.call(execute, profile, "status", "status", resources, {}, guard)
    assert {row["data"]["resource"]["state"] for row in current["results"]} == {"off"}
