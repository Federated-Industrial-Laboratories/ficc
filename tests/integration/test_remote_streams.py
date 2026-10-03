# SPDX-License-Identifier: Apache-2.0
"""Qualify distinct project users across real remote HTTP and WebSocket paths."""

import asyncio
import contextlib
import json
import secrets

import httpx
import pytest
from remote_streams.lab import laboratory
from remote_streams.workflows import (
    attached,
    detached,
    download,
    proof,
    request,
    terminal,
    until,
    verify_download,
)
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_distinct_remote_peers_observe_transfer_resize_and_persist(count):
    with laboratory() as lab:
        async with contextlib.AsyncExitStack() as cleanup:
            sessions = []
            for _ in range(count + 1):
                index = lab.member()
                client, value = await lab.login(index)
                cleanup.push_async_callback(client.aclose)
                sessions.append((client, value))
            assert len({value["principal"]["id"] for _, value in sessions}) == count + 1
            control, _ = sessions[-1]
            control_record = await terminal(control, lab.node["id"], "control")
            async with attached(lab, control, control_record) as (healthy, _):
                await proof(healthy, "healthy_initial")
                terminal_ids, workspace_ids, digests = set(), set(), set()
                for index, (client, value) in enumerate(sessions[:-1]):
                    nodes = (await request(client, "GET", "/api/v1/nodes"))["nodes"]
                    assert len(nodes) == 1 and nodes[0]["id"] == lab.node["id"]
                    assert nodes[0]["resources"]["cpu_count"] > 0
                    record = await terminal(client, lab.node["id"], index)
                    terminal_ids.add(record["id"])
                    async with attached(lab, client, record) as (socket, ticket):
                        await proof(socket, f"peer_{index:02}")
                        await socket.send(json.dumps({"type": "resize", "cols": 101, "rows": 37}))
                        await socket.send(b"stty size; printf '\\123IZE_DONE\\n'\n")
                        assert b"37 101" in await until(socket, b"SIZE_DONE")
                    await detached(client, record)
                    if index == count - 1:
                        address = lab.origin.replace("https://", "wss://") + ticket["websocket_path"]
                        async with connect(address, ssl=lab.tls, origin=lab.origin, proxy=None) as replay:
                            await replay.send(json.dumps({"type": "auth", "ticket": ticket["ticket"]}))
                            assert json.loads(await replay.recv())["state"] == "denied"
                    data = (f"Distinct remote file {index:02}\n".encode() * 14000) + bytes([index])
                    filename = f"peer-{index:02}.bin"
                    (lab.files / filename).write_bytes(data)
                    path, item = await download(client, lab.root["id"], filename)
                    await verify_download(client, path, data)
                    digests.add(item["sha256"])
                    workspace = await request(client, "POST", "/api/v1/workspaces",
                                              json={"name": f"Remote workspace {index:02}"})
                    workspace_ids.add(workspace["id"])
                    assert (await request(client, "GET", "/api/v1/workspaces/" + workspace["id"]))["name"] == workspace["name"]
                    assert (await control.get(f"/api/v1/terminals/{record['id']}")).status_code == 404
                    await proof(healthy, f"healthy_{index:02}")
                assert len(terminal_ids) == len(workspace_ids) == len(digests) == count
            await detached(control, control_record)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_revocation_and_disconnect_close_live_streams_without_harming_peer(count):
    with laboratory() as lab:
        async with contextlib.AsyncExitStack() as cleanup:
            clients = []
            for _ in range(count + 1):
                client, _ = await lab.login(lab.member())
                cleanup.push_async_callback(client.aclose)
                clients.append(client)
            for client in clients[:-1]:
                assert (await client.get("/api/v1/nodes")).status_code == 200
            target, control = clients[count - 1], clients[-1]
            target_record = await terminal(target, lab.node["id"], "revoked")
            control_record = await terminal(control, lab.node["id"], "unaffected")
            content = secrets.token_bytes(1024) * 32768
            (lab.files / "revocation.bin").write_bytes(content)
            path, _ = await download(target, lab.root["id"], "revocation.bin")
            async with attached(lab, control, control_record) as (healthy, _):
                async with attached(lab, target, target_record) as (socket, _):
                    await proof(socket, "before_revocation")
                    async with target.stream("GET", path) as response:
                        assert response.status_code == 200
                        chunks = response.aiter_bytes(65536)
                        size = len(await anext(chunks))
                        lab.revoke(count - 1)
                        with contextlib.suppress(httpx.RemoteProtocolError):
                            async for data in chunks:
                                size += len(data)
                        assert size < len(content), "The revoked file stream delivered its remaining body."
                    async with asyncio.timeout(5):
                        try:
                            while True:
                                value = await socket.recv()
                                if isinstance(value, str):
                                    assert json.loads(value)["state"] == "denied"
                        except ConnectionClosed:
                            pass
                assert (await target.get("/api/v1/nodes")).status_code == 401
                assert (await target.get(path)).status_code == 401
                await proof(healthy, "after_revocation")
                statuses = [(await client.get("/api/v1/nodes")).status_code for client in clients[:count - 1]]
                assert all(status == 200 for status in statuses)
            await detached(control, control_record)
            record = await terminal(control, lab.node["id"], "gateway-disconnect")
            async with attached(lab, control, record) as (socket, _):
                await proof(socket, "before_disconnect")
                lab.gateway.close()
                with pytest.raises(ConnectionClosed):
                    async with asyncio.timeout(5):
                        while True:
                            await socket.recv()
            lab.gateway.start()
            await detached(control, record)
            assert (await control.get("/api/v1/nodes")).status_code == 200
