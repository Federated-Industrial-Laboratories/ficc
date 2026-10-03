# SPDX-License-Identifier: Apache-2.0
"""Qualify project VM consoles through the real provider, native bridge and TLS."""

import asyncio
import contextlib
import json

import pytest
from remote_streams.lab import SCOPES, laboratory
from remote_streams.modules import prepare, reference
from remote_streams.viewer import display, frame, input_event
from remote_streams.workflows import request
from websockets.asyncio.client import connect


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_distinct_project_viewers_use_real_vm_and_release_revoked_sessions(count):
    with laboratory(display=True) as lab:
        async with contextlib.AsyncExitStack() as cleanup:
            clients = []
            for _ in range(count + 1):
                client, _ = await lab.login(lab.member(SCOPES + ["vm:read", "vm:console"]))
                cleanup.push_async_callback(client.aclose)
                clients.append(client)
            context = await prepare(lab, clients[0])
            healthy = clients[-1]
            control_ref = await reference(lab, healthy, context)
            references = set()
            async with display(lab, healthy, control_ref) as (control, _, _):
                for index, client in enumerate(clients[:-1]):
                    selected = await reference(lab, client, context)
                    references.add(selected)
                    assert (await healthy.post(f"/api/v1/viewers/{selected}/tickets")).status_code == 409
                    async with display(lab, client, selected) as (socket, ticket, initial):
                        await input_event(socket, "size", 960, 600)
                        await input_event(socket, "key", ord("A") + index % 26, 1)
                        await input_event(socket, "key", ord("A") + index % 26, 0)
                        assert await frame(socket) != initial
                        await frame(control)
                        if index == count - 1:
                            lab.revoke(index)
                            async with asyncio.timeout(5):
                                await socket.wait_closed()
                            assert (await client.get("/api/v1/nodes")).status_code == 401
                    async def released():
                        for _ in range(50):
                            response = await client.post(f"/api/v1/viewers/{selected}/tickets")
                            if response.status_code == 401 or response.status_code == 409 and response.json()["error"]["code"] == "viewer_expired":
                                return
                            await asyncio.sleep(.05)
                        raise AssertionError("The viewer remained attached after disconnect.")
                    await released()
                    url = lab.origin.replace("https://", "wss://") + f"/api/v1/viewers/{selected}/stream"
                    async with connect(url, ssl=lab.tls, origin=lab.origin, proxy=None) as replay:
                        await replay.send(json.dumps({"type": "auth", "ticket": ticket["ticket"]}))
                        result = json.loads(await replay.recv())
                        assert result["type"] == "error"
                    await input_event(control, "key", ord("z"), 1)
                    await input_event(control, "key", ord("z"), 0)
                    await frame(control)
                    assert (await request(healthy, "GET", "/api/v1/nodes"))["nodes"]
                assert len(references) == count
