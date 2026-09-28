# SPDX-License-Identifier: Apache-2.0
"""Detect output bursts that must wait for browser frame acknowledgements."""

import asyncio
import json

import pytest
from test_viewer_configuration import rdp_config

from ficc.viewer import wire
from ficc.viewer_stream import bridge


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("authentication", ["none", "rfb-password", "vmconnect"])
async def test_frame_burst_waits_for_browser_and_cleans_up(monkeypatch, count, authentication):
    packets = asyncio.Queue()
    await packets.put((wire.DISPLAY, b"".join(wire.instruction("sync", index) for index in range(count))))
    controls = asyncio.Queue()
    state = {"sent": 0, "closed": 0, "peak": 0, "acknowledged": 0}

    class Complete(Exception):
        pass

    class Native:
        def __init__(self, runtime, *, protocol="vnc"):
            assert protocol == ("rdp" if authentication == "vmconnect" else "vnc")
            self.errors = asyncio.create_task(asyncio.sleep(60))

        async def start(self, check):
            check()

        async def send(self, kind, data):
            if kind == wire.CONFIG:
                config = json.loads(data)
                expected = {"version": 1, "protocol": "vnc"}
                if authentication == "rfb-password":
                    expected["password"] = "Test1234"
                elif authentication == "vmconnect":
                    expected = rdp_config(count)
                assert config == expected
            if kind == wire.DISPLAY:
                state["acknowledged"] += 1
                if state["acknowledged"] == count:
                    raise Complete()

        async def receive(self):
            return await packets.get()

        async def close(self):
            state["closed"] += 1

    class Provider:
        def __init__(self, args):
            pass

        async def start(self, header, authentication):
            return "Test1234" if authentication == "rfb-password" else None

        async def read(self):
            await asyncio.sleep(60)

        async def close(self):
            state["closed"] += 1

    class Socket:
        async def send_bytes(self, data):
            assert b"Test1234" not in data and b"Secret" not in data
            state["sent"] += 1
            state["peak"] = max(state["peak"], state["sent"] - state["acknowledged"])
            await controls.put(json.dumps({"type": "ack", "bytes": len(data)}))
            await controls.put(json.dumps({"type": "input", "instruction": data.decode()}))

        async def receive_text(self):
            value = await controls.get()
            await asyncio.sleep(0.002)
            return value

    monkeypatch.setattr("ficc.viewer_stream.ViewerProcess", Native)
    monkeypatch.setattr("ficc.viewer_stream.ProviderStream", Provider)
    class TCPProvider(Provider):
        def __init__(self):
            pass

        async def start(self, connection, check):
            check()
            assert connection == {"host": "registered.example", "port": 2179, "configuration": rdp_config(count)}
            return json.dumps(connection["configuration"]).encode()

    monkeypatch.setattr("ficc.viewer_stream.TCPProviderStream", TCPProvider)
    options = {"authentication": authentication}
    if authentication == "vmconnect":
        options = {"connection": {"host": "registered.example", "port": 2179, "configuration": rdp_config(count)}}
    async with asyncio.timeout(5):
        with pytest.raises(Complete):
            await bridge(Socket(), None, [], b"", lambda: None, **options)
    assert state["closed"] == 2 and state["sent"] == count and state["peak"] <= 3
