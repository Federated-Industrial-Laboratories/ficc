# SPDX-License-Identifier: Apache-2.0
"""Keep current authorization and unrelated requests responsive during ready display bursts."""

import asyncio
import json

import pytest

from ficc.errors import Failure
from ficc.viewer import wire
from ficc.viewer_stream import bridge


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_output_burst_yields_before_delivering_revoked_packets(monkeypatch, count):
    state = {"sent": [], "revoked": False, "closed": 0}
    sent = asyncio.Event()
    revoked = asyncio.Event()
    batches = [b"".join(wire.instruction("size", 0, 320 + index, 240 + offset)
                       for offset in range(64)) for index in range(count + 8)]
    packets = b"".join(batches)

    class Native:
        def __init__(self, runtime, *, protocol):
            self.errors = asyncio.create_task(asyncio.sleep(60))
            self.pending = True

        async def start(self, check):
            check()

        async def send(self, kind, data):
            assert kind == wire.CONFIG and json.loads(data)["protocol"] == "vnc"

        async def receive(self):
            if self.pending:
                self.pending = False
                return wire.DISPLAY, packets
            await asyncio.Future()

        async def close(self):
            state["closed"] += 1

    class Provider:
        def __init__(self, args, check):
            check()

        async def start(self, header, authentication):
            return None

        async def read(self):
            await asyncio.Future()

        async def close(self):
            state["closed"] += 1

    class Socket:
        async def send_bytes(self, data):
            assert data == batches[len(state["sent"])]
            state["sent"].append(data)
            if len(state["sent"]) == count:
                sent.set()

        async def receive_text(self):
            await asyncio.Future()

    def check():
        if state["revoked"]:
            raise Failure("denied", "Display authority changed.", 403)

    async def other_request():
        await sent.wait()
        state["revoked"] = True
        revoked.set()

    monkeypatch.setattr("ficc.viewer_stream.ViewerProcess", Native)
    monkeypatch.setattr("ficc.viewer_stream.ProviderStream", Provider)
    request = asyncio.create_task(other_request())
    try:
        async with asyncio.timeout(3):
            with pytest.raises(Failure, match="Display authority changed"):
                await bridge(Socket(), None, [], b"{}\n", check)
            await request
        assert revoked.is_set()
        assert state["sent"] == batches[:count]
        assert state["closed"] == 2
    finally:
        request.cancel()
        await asyncio.gather(request, return_exceptions=True)
