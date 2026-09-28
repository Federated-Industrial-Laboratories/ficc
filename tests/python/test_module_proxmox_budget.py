# SPDX-License-Identifier: Apache-2.0
"""Keep durable power commit time separate from module read and console bounds."""

import io
from types import SimpleNamespace

import pytest
from ficc_node import proxmox_rpc as rpc
from ficc_node import proxmox_spec as spec
from test_module_proxmox_protocol import request

from ficc.providers import proxmox


@pytest.mark.parametrize("size", [1, 64])
@pytest.mark.parametrize("action", ["apply", "receipt", "status"])
def test_transport_extends_only_host_commit(monkeypatch, size, action):
    async def run():
        value = request(size)
        value["action"] = action
        if action == "status":
            value["parameters"] = {"uuids": [row["uuid"] for row in value["parameters"]["intent"]["expected"]]}
        budgets = []
        async def command(node, command, payload, check, timeout):
            check()
            assert spec.decode(payload) == value
            budgets.append(timeout)
            return 0, b'{"version":1,"data":{}}', b""
        service = SimpleNamespace(ssh=SimpleNamespace(command=command))
        monkeypatch.setattr(proxmox, "validate", lambda data, request: data)
        transport = proxmox.Transport(service)
        profile = {"id": value["profile"], "provider": value["provider"]}
        assert await transport.request({}, profile, action, value["parameters"], lambda: None) == {}
        assert budgets == [14 if action == "apply" else 8]
        assert transport.pending == 0
    import asyncio
    asyncio.run(run())


@pytest.mark.parametrize("size", [1, 64])
@pytest.mark.parametrize("action", ["apply", "receipt"])
def test_node_commit_budget_includes_input_time(monkeypatch, size, action):
    value = request(size)
    value["action"] = action
    calls = []
    monkeypatch.setattr(rpc.signal, "signal", lambda *args: None)
    monkeypatch.setattr(rpc.signal, "alarm", lambda seconds: calls.append(("initial", seconds)))
    monkeypatch.setattr(rpc.signal, "setitimer", lambda kind, seconds: calls.append(("remaining", seconds)))
    times = iter((100, 102.5))
    monkeypatch.setattr(rpc.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(rpc.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(spec.encode(value))))
    output = io.BytesIO()
    monkeypatch.setattr(rpc.sys, "stdout", SimpleNamespace(buffer=output))
    monkeypatch.setattr(rpc, "dispatch", lambda request: {"received": request["action"]})
    assert rpc.main() == 0
    assert calls == ([("initial", 6), ("remaining", 9.5)] if action == "apply" else [("initial", 6)])
    assert spec.decode(output.getvalue()) == {"version": 1, "data": {"received": action}}
    assert spec.APPLY_SECONDS >= spec.REQUEST_SECONDS + spec.BRIDGE_SECONDS + 1
    assert spec.APPLY_TRANSPORT_SECONDS >= spec.APPLY_SECONDS + 2
