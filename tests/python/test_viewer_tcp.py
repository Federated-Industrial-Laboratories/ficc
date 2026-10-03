# SPDX-License-Identifier: Apache-2.0
"""Check bounded registered TCP relay, exact private configuration and cleanup."""

import asyncio
import json

import pytest
from test_viewer_configuration import rdp_config

from ficc.viewer_tcp import TCPProviderStream


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_registered_tcp_transfers_distinct_bytes_and_closes(count):
    closed = asyncio.Queue()

    async def peer(reader, writer):
        try:
            while data := await reader.read(32768):
                writer.write(data[::-1])
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            await closed.put(True)

    server = await asyncio.start_server(peer, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with asyncio.timeout(10):
            for index in range(count):
                client = TCPProviderStream()
                checked = []
                config = rdp_config(index)
                try:
                    data = await client.start({"host": "127.0.0.1", "port": port, "configuration": config},
                                              lambda: checked.append(True))
                    assert json.loads(data) == config and len(checked) == 2
                    packet = f"Distinct stream {index}".encode()
                    await client.write(packet)
                    assert await client.read() == packet[::-1]
                finally:
                    await client.close()
                assert await closed.get()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("change", [
    {"url": "https://other.example"}, {"host": "http://other.example"}, {"host": "user@other.example"},
    {"host": "other.example\n"}, {"host": "fe80::1%eth0"}, {"port": True}, {"port": 0},
    {"port": 65536}, {"port": "2179"}, {"configuration": {"version": 1, "protocol": "vnc"}},
    {"configuration": {**rdp_config(), "ignore-cert": True}},
])
async def test_invalid_tcp_connection_refuses_before_network(monkeypatch, change):
    calls = []

    async def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError("Invalid configuration attempted a connection")

    monkeypatch.setattr(asyncio, "open_connection", forbidden)
    client = TCPProviderStream()
    with pytest.raises(ValueError):
        await client.start({"host": "127.0.0.1", "port": 2179, "configuration": rdp_config(), **change}, lambda: None)
    await client.close()
    assert calls == []


async def test_authority_loss_during_connect_leaves_socket_for_owned_cleanup(monkeypatch):
    class Revoked(Exception):
        pass

    class Writer:
        closed = False

        def close(self):
            self.closed = True

        async def wait_closed(self):
            pass

    writer = Writer()
    state = {"permitted": True}

    async def connect(*args, **kwargs):
        state["permitted"] = False
        return asyncio.StreamReader(), writer

    def check():
        if not state["permitted"]:
            raise Revoked()

    monkeypatch.setattr(asyncio, "open_connection", connect)
    client = TCPProviderStream()
    try:
        with pytest.raises(Revoked):
            await client.start({"host": "127.0.0.1", "port": 2179, "configuration": rdp_config()}, check)
    finally:
        await client.close()
    assert writer.closed
