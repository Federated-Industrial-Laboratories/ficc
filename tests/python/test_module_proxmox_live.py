# SPDX-License-Identifier: Apache-2.0
"""Qualify real Proxmox enrollment, module grants, tasks and private display."""

import asyncio
import json
import os
import secrets
from pathlib import Path

import pytest
from test_module_proxmox_live_support import checked
from test_module_proxmox_live_support import live_pve as live_pve

from ficc.errors import Failure
from ficc.providers.proxmox import COMMAND
from ficc.viewer.wire import instruction, parse
from ficc.viewer_stream import bridge


def test_live_qualified_profile_and_readonly_module(live_pve):
    from ficc_node.proxmox_compat import READ_BUILDS
    live = live_pve
    profile = live.service.proxmox.records.profile(live.node["id"])
    provider = profile["provider"]
    assert (provider["version"], provider["fingerprint"]) in READ_BUILDS
    rows = live.fixture_rows()
    assert {row["values"]["state"] for row in rows.values()} == {"off"}
    selected = rows["ficc-pve-a"]["id"]
    live.invoke("preview-start", {"vm_ids": [selected]}, status=403)
    live.invoke("open-console", {"vm_ids": [selected]}, status=403)


def test_live_inventory64_through_installed_helper_and_sandbox(live_pve):
    prefix = os.environ.get("FICC_PROXMOX_TEST_BATCH")
    if not prefix:
        pytest.skip("An explicit owned64-definition fixture batch is required.")
    first, second = live_pve.inventory(), live_pve.inventory(64)
    assert len(first["rows"]) == 64 and "offset 64" in first["notice"]
    assert len(second["rows"]) == 2 and not second["notice"]
    rows = [row for row in first["rows"] + second["rows"] if row["values"]["name"].startswith(prefix + "-")]
    assert len(rows) == 64 and len({row["id"] for row in rows}) == 64
    assert {row["values"]["state"] for row in rows} == {"off"}
    host = live_pve.service.proxmox
    profile = host.records.profile(live_pve.node["id"])
    result = live_pve.client.portal.call(host.transport.request, live_pve.node, profile,
        "status", {"uuids": [row["id"].rsplit("-", 1)[1] for row in rows]}, lambda: None)
    assert len(result["results"]) == 64 and all("data" in row for row in result["results"])


def display(live, selected):
    def guard():
        live.service.authorize(live.actor, "vm:console", live.node["id"])
        live.service.modules.require(live.digest, "vm:console", [live.node["id"]])

    class Complete(Exception):
        pass

    async def run():
        queue = asyncio.Queue()
        counts = {"img": 0, "end": 0, "size": 0, "sync": 0}
        class Socket:
            async def send_bytes(self, data):
                value = parse(data.decode(), 65536)
                if value[0] in counts:
                    counts[value[0]] += 1
                await queue.put(json.dumps({"type": "ack", "bytes": len(data)}))
                if value[0] == "sync":
                    if counts["sync"] > 1 and counts["end"] and counts["size"]:
                        raise Complete()
                    await queue.put(json.dumps({"type": "input", "instruction": instruction("sync", value[1]).decode()}))
            async def receive_text(self):
                return await queue.get()
        host = live.service.proxmox
        descriptor = await host.console(live.actor, live.digest, live.context["instance_id"], live.node["id"], selected, guard)
        assert descriptor["graphics"]["authentication"] == "rfb-password"
        assert descriptor["graphics"]["audio"] is False and "password" not in descriptor["graphics"]
        arguments, header = await host.console_command(descriptor, guard)
        with pytest.raises(Complete):
            async with asyncio.timeout(40):
                await bridge(Socket(), Path(os.environ["FICC_VIEWER_RUNTIME"]), arguments, header, guard,
                             authentication="rfb-password")
        assert all(counts.values())
        return descriptor
    return live.client.portal.call(run), guard


def test_live_confirmed_lifecycle_no_replay_console_and_revoke(live_pve, monkeypatch):
    live = live_pve
    if not os.environ.get("FICC_VIEWER_RUNTIME"):
        pytest.skip("A qualified native display runtime is required.")
    rows = live.fixture_rows()
    assert {row["values"]["state"] for row in rows.values()} == {"off"}
    selected = rows["ficc-pve-a"]["id"]
    live.invoke("preview-start", {"vm_ids": [selected]}, status=403)
    live.invoke("open-console", {"vm_ids": [selected]}, status=403)
    grants = live.grants + [{"capability": capability, "target_ids": [live.node["id"]]}
                           for capability in ("vm:power", "vm:console")]
    live.activate(grants)
    previous = live.service.ssh.command
    dispatched = []
    async def observe(node, command, payload=b"", check=None, timeout=10):
        if command == COMMAND and json.loads(payload)["action"] == "apply":
            dispatched.append(json.loads(payload)["parameters"]["operation"])
        return await previous(node, command, payload, check=check, timeout=timeout)
    monkeypatch.setattr(live.service.ssh, "command", observe)
    preview = live.preview("start", selected)
    live.activate(live.grants)
    live.commit(preview, status=403)
    assert not dispatched and live.fixture_rows()["ficc-pve-a"]["values"]["state"] == "off"
    live.activate(grants)
    preview = live.preview("start", selected)
    checked(live.client.post("/api/v1/module-vms/commit", json={**live.context,
        "preview_id": preview["preview_id"], "confirm": False},
        headers={"Idempotency-Key": secrets.token_hex(16)}), 422)
    assert not dispatched
    nonce = secrets.token_hex(16)
    assert live.capture("arm", nonce) == {"armed": True}
    key = secrets.token_hex(16)
    started = live.commit(preview, key)
    assert started["targets"][0]["state"] == "accepted"
    assert live.commit(preview, key)["id"] == started["id"] and len(dispatched) == 1
    observed = live.wait_operation(started["id"])
    assert observed["targets"][0]["state"] == "observed"
    assert observed["targets"][0]["task"]["exitstatus"] == "OK"
    live.wait_ready(nonce)
    opened = live.invoke("open-console", {"vm_ids": [selected]})
    assert set(opened["results"][0]["data"]) == {"viewer_ref"}
    assert isinstance(opened["results"][0]["data"]["viewer_ref"], str)
    descriptor, guard = display(live, selected)
    live.activate(live.grants)
    with pytest.raises(Failure):
        live.client.portal.call(live.service.proxmox.console_command, descriptor, guard)
    live.activate(grants)
    shutdown = live.commit(live.preview("shutdown", selected))
    observed = live.wait_operation(shutdown["id"])
    assert observed["targets"][0]["observed_state"] == "off" and len(dispatched) == 2
    assert live.forget(started) == live.forget(shutdown) == {"removed": True}
    assert {row["values"]["state"] for row in live.fixture_rows().values()} == {"off"}
