# SPDX-License-Identifier: Apache-2.0
"""Check display tickets, current authority and cleanup without provider access."""

import asyncio
from functools import partial
from types import SimpleNamespace

import pytest
from conftest import node
from starlette.websockets import WebSocketDisconnect
from test_viewer_configuration import rdp_config

from ficc.errors import Failure
from ficc.viewer.configuration import ready


def setup(console, tmp_path, monkeypatch):
    client, service = console
    service.store.save_node(node())
    runtime = tmp_path / "runtime"
    (runtime / "sbin").mkdir(parents=True)
    (runtime / "sbin/guacd").write_text("fixture")
    service.settings.viewer_runtime = runtime
    actor = service.auth.resolve(client.cookies.get("ficc_session")).id
    state = {"permitted": True, "attached": 0, "closed": 0}

    def check():
        if not state["permitted"]:
            raise Failure("denied", "Access was revoked.", 403)

    async def console_descriptor(*args):
        check()
        return {"digest": "0" * 64, "node_id": "node-0", "profile": {}, "vm_id": "bound-vm",
                "graphics": {"protocol": "vnc", "authentication": "rfb"}}

    async def command(*args):
        check()
        return [], b""

    async def bridge(socket, runtime, arguments, header, guard, *, authentication="none"):
        assert authentication == "rfb"
        assert ready(b'{"version":1,"ready":true}', authentication) is None
        state["attached"] += 1
        try:
            await socket.send_bytes(b"4.sync,1.1;")
            while True:
                await asyncio.sleep(0.01)
                guard()
        finally:
            state["closed"] += 1

    monkeypatch.setattr(service.vms, "groups", lambda *args: ({}, {"node-0": ["bound-vm"]}))
    monkeypatch.setattr(service.vms, "console", console_descriptor)
    monkeypatch.setattr(service.vms, "console_command", command)
    monkeypatch.setattr(service.vms, "profile", lambda *args: (node(), {}))
    monkeypatch.setattr(service.vms, "guard", lambda *args: check())
    monkeypatch.setattr("ficc.viewer_routes.bridge", bridge)
    call = SimpleNamespace(action_capabilities=["vm:console"], parameters={"vm_ids": ["bound-vm"]},
                           target_ids=["node-0"], package_digest="0" * 64, check=check)
    return actor, state, call


@pytest.mark.parametrize("count", [1, 64])
def test_bounded_references_actor_expiry_and_single_use(console, tmp_path, monkeypatch, count):
    client, service = console
    actor, state, call = setup(console, tmp_path, monkeypatch)
    for _ in range(count):
        result = client.portal.call(service.viewers.issue, actor, call, "instance")
        reference = result[0]["data"]["viewer_ref"]
        route = f"/api/v1/viewers/{reference}"
        denied = client.post(route + "/tickets", headers={"X-CSRF-Token": "bad"})
        assert denied.status_code == 403
        response = client.post(route + "/tickets")
        assert response.status_code == 200 and response.json()["system"] == "Machine 0"
        token = response.json()["ticket"]
        with client.websocket_connect(route + "/stream", headers={"Origin": service.settings.origin, "Host": "127.0.0.1:8170"}) as socket:
            socket.send_json({"type": "auth", "ticket": token})
            assert socket.receive_bytes() == b"4.sync,1.1;"
            state["permitted"] = False
            assert socket.receive_json()["code"] == "denied"
            with pytest.raises(WebSocketDisconnect):
                socket.receive_bytes()
        assert not service.viewers.active
        state["permitted"] = True
        with client.websocket_connect(route + "/stream", headers={"Origin": service.settings.origin, "Host": "127.0.0.1:8170"}) as socket:
            socket.send_json({"type": "auth", "ticket": token})
            assert socket.receive_json()["code"] == "viewer_ticket"
    assert state["attached"] == state["closed"] == count


def test_origin_reference_capacity_and_current_authority(console, tmp_path, monkeypatch):
    client, service = console
    actor, state, call = setup(console, tmp_path, monkeypatch)
    for _ in range(64):
        result = client.portal.call(service.viewers.issue, actor, call, "instance")
    with pytest.raises(Failure, match="reference limit"):
        client.portal.call(service.viewers.issue, actor, call, "instance")
    reference = result[0]["data"]["viewer_ref"]
    with pytest.raises(Failure):
        service.viewers.current(reference, "different-actor")
    route = f"/api/v1/viewers/{reference}"
    for suffix, origin in [("", "http://untrusted.example"), ("?ticket=forbidden", service.settings.origin)]:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(route + "/stream" + suffix, headers={"Origin": origin, "Host": "127.0.0.1:8170"}):
                pass
    state["permitted"] = False
    assert client.post(route + "/tickets").status_code == 403
    state["permitted"] = True
    service.viewers.references[reference]["expires"] = 0
    assert client.post(route + "/tickets").status_code == 409


@pytest.mark.parametrize("count", [1, 64])
def test_registered_rdp_endpoint_uses_private_connection_and_current_authority(console, tmp_path, monkeypatch, count):
    client, service = console
    runtime = tmp_path / "runtime"
    (runtime / "sbin").mkdir(parents=True)
    (runtime / "sbin/guacd").write_text("fixture")
    service.settings.viewer_runtime = runtime
    actor = service.auth.resolve(client.cookies.get("ficc_session")).id
    state = {"permitted": True, "index": 0, "attached": 0}

    def check(*args):
        if not state["permitted"]:
            raise Failure("denied", "Access was revoked.", 403)

    async def descriptor(*args):
        return {"provider": "fixture", "digest": "0" * 64, "node_id": "endpoint-0", "profile": {},
                "vm_id": rdp_config(state["index"])["vm_id"], "graphics": {"protocol": "rdp"}}

    async def connect(value, guard):
        guard()
        config = rdp_config(state["index"])
        assert value["vm_id"] == config["vm_id"]
        return {"host": "registered.example", "port": 2179, "configuration": config}

    async def relay(socket, runtime, arguments, header, guard, *, connection):
        assert not arguments and not header
        assert connection == await connect(await descriptor(), guard)
        state["attached"] += 1
        await socket.send_bytes(b"4.sync,1.1;")
        while True:
            await asyncio.sleep(0.01)
            guard()

    host = SimpleNamespace(guard=check, console=descriptor, console_connection=connect,
        groups=lambda *args: ({}, {"endpoint-0": ["selected"]}), profile=lambda *args: ({"name": "Registered VM host"}, {}))
    service.vm_providers.hosts["fixture"] = host
    monkeypatch.setattr("ficc.viewer_routes.bridge", relay)
    call = SimpleNamespace(action_capabilities=["vm:console"], parameters={"vm_ids": ["selected"]},
                           target_ids=["endpoint-0"], package_digest="0" * 64, check=check)
    for index in range(count):
        state["index"], state["permitted"] = index, True
        result = client.portal.call(partial(service.viewers.issue, actor, call, "instance", provider="fixture"))
        route = "/api/v1/viewers/" + result[0]["data"]["viewer_ref"]
        response = client.post(route + "/tickets")
        assert response.status_code == 200 and response.json()["system"] == "Registered VM host"
        assert "Secret" not in response.text and "registered.example" not in response.text
        with client.websocket_connect(route + "/stream", headers={"Origin": service.settings.origin, "Host": "127.0.0.1:8170"}) as socket:
            socket.send_json({"type": "auth", "ticket": response.json()["ticket"]})
            assert socket.receive_bytes() == b"4.sync,1.1;"
            state["permitted"] = False
            assert socket.receive_json()["code"] == "denied"
        assert not service.viewers.active and not service.viewers.references
    assert state["attached"] == count


@pytest.mark.parametrize("count", [1, 64])
def test_adapter_console_selection_uses_real_endpoint_and_exact_profile(console, tmp_path, monkeypatch, count):
    client, service = console
    actor, _, call = setup(console, tmp_path, monkeypatch)
    async def select(owner, requested, instance):
        assert owner == actor and instance == "instance"
        return {"provider": "adapter-fixture", "digest": call.package_digest,
                "node_id": "endpoint-0", "profile_id": requested.parameters["profile_id"],
                "profile": {}, "vm_id": requested.parameters["vm_ids"][0], "graphics": {"protocol": "rdp"}}
    profile_reads = []
    def profile(identity):
        profile_reads.append(identity)
        return {"name": "Separate provider endpoint"}, {}
    host = SimpleNamespace(console_request=select, profile=profile, guard=lambda *args: call.check())
    service.vm_providers.hosts["adapter-fixture"] = host
    call.target_ids = ["endpoint-0"]
    for index in range(count):
        identity = f"{index:032x}"
        call.parameters = {"profile_id": identity, "vm_ids": [f"vm-{index}"]}
        result = client.portal.call(partial(service.viewers.issue, actor, call, "instance", provider="adapter-fixture"))
        response = client.post(f"/api/v1/viewers/{result[0]['data']['viewer_ref']}/tickets")
        assert response.status_code == 200 and response.json()["system"] == "Separate provider endpoint"
        assert profile_reads[-1] == identity
    service.viewers.references.clear()
    call.target_ids = ["another-endpoint"]
    with pytest.raises(Failure, match="outside this panel"):
        client.portal.call(partial(service.viewers.issue, actor, call, "instance", provider="adapter-fixture"))
    assert not service.viewers.references and service.viewers.pending == 0
