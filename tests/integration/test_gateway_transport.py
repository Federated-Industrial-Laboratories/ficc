# SPDX-License-Identifier: Apache-2.0
"""Exercise supplied gateway connection retirement and diagnostic redaction."""

import asyncio
import contextlib
import json
import os
import socket
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]


def binary():
    value = os.environ.get("FICC_TEST_CADDY")
    if not value:
        pytest.skip("Select the qualified Caddy executable for real gateway checks.")
    return value


def configuration(folder, port, routes="controller.caddy"):
    source = (ROOT / "packaging/remote/Caddyfile").read_text()
    global_options = source[:source.index("\n}\n") + 3]
    global_options = global_options.replace("admin unix//run/ficc-gateway/admin.sock", "admin off")
    rules = (ROOT / "packaging/remote" / routes).read_text()
    rules = rules.replace("unix//run/ficc-controller/gateway.sock", "unix/" + str(folder / "upstream.sock"))
    config = global_options + f"\nhttp://127.0.0.1:{port} {{\n log\n respond /ready 204\n" + rules + "\n}\n"
    path = folder / "Caddyfile"
    path.write_text(config)
    return path


@contextlib.asynccontextmanager
async def gateway(folder):
    with socket.socket() as selected:
        selected.bind(("127.0.0.1", 0))
        port = selected.getsockname()[1]
    config = configuration(folder, port)
    env = {**os.environ, "FICC_PUBLIC_ADDRESS": f"127.0.0.1:{port}",
           "FICC_GATEWAY_SECRET": "gateway-test-canary", "GOMAXPROCS": "2",
           "XDG_DATA_HOME": str(folder / "data"), "XDG_CONFIG_HOME": str(folder / "config")}
    with (folder / "gateway.log").open("wb") as log:
        process = await asyncio.create_subprocess_exec(binary(), "run", "--config", str(config),
                                                       "--adapter", "caddyfile", env=env,
                                                       stdout=log, stderr=log)
        try:
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", trust_env=False,
                                         timeout=10, limits=httpx.Limits(max_connections=64)) as client:
                for _ in range(100):
                    assert process.returncode is None, "The isolated gateway exited."
                    try:
                        if (await client.get("/ready")).status_code == 204:
                            break
                    except httpx.TransportError:
                        pass
                    await asyncio.sleep(.05)
                else:
                    raise AssertionError("The isolated gateway did not start.")
                yield client
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except TimeoutError:
                    process.kill()
                    await process.wait()


class Backend:
    def __init__(self, count):
        self.count = count
        self.connections = 0
        self.requests = []
        self.arrived = {}
        self.barriers = {}
        self.writers = set()

    async def serve(self, reader, writer):
        self.connections += 1
        identity = self.connections
        self.writers.add(writer)
        try:
            while True:
                try:
                    header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                except (asyncio.IncompleteReadError, TimeoutError):
                    return
                lines = header.decode("ascii").split("\r\n")
                fields = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
                body = await reader.readexactly(int(fields.get("Content-Length", "0")))
                request = json.loads(body)
                self.requests.append(request["id"])
                if request.get("fail"):
                    writer.transport.abort()
                    return
                generation = request["generation"]
                self.arrived[generation] = self.arrived.get(generation, 0) + 1
                barrier = self.barriers.setdefault(generation, asyncio.Event())
                if self.arrived[generation] == self.count:
                    barrier.set()
                await asyncio.wait_for(barrier.wait(), 8)
                output = json.dumps({"connection": identity, "id": request["id"]}).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Set-Cookie: fixture=response-header-canary\r\nContent-Length: "
                             + str(len(output)).encode() + b"\r\n\r\n" + output)
                await writer.drain()
        finally:
            self.writers.discard(writer)
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    async def close(self):
        for writer in list(self.writers):
            writer.close()
        await asyncio.gather(*(writer.wait_closed() for writer in list(self.writers)), return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_gateway_retires_upstream_connections_before_backend_idle_expiry(tmp_path, count):
    binary()
    backend = Backend(count)
    server = await asyncio.start_unix_server(backend.serve, path=str(tmp_path / "upstream.sock"))
    try:
        async with server, gateway(tmp_path) as client:
            batches = []
            for generation in (1, 2):
                identities = [f"request-{generation}-{index}" for index in range(count)]
                responses = await asyncio.gather(*(client.post("/api/v1/probe", json={
                    "id": identity, "generation": generation}) for identity in identities))
                assert all(response.status_code == 200 for response in responses)
                values = [response.json() for response in responses]
                assert [value["id"] for value in values] == identities
                connections = {value["connection"] for value in values}
                assert len(connections) == count
                batches.append(connections)
                if generation == 1:
                    await asyncio.sleep(2)
            assert not batches[0] & batches[1], "The proxy reused connections beyond its safe idle interval."
        assert len(backend.requests) == len(set(backend.requests)) == 2 * count
        assert "response-header-canary" not in (tmp_path / "gateway.log").read_text()
    finally:
        server.close()
        await server.wait_closed()
        await backend.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_gateway_errors_remove_headers_and_callback_values_without_replaying_posts(tmp_path, count):
    binary()
    backend = Backend(count)
    server = await asyncio.start_unix_server(backend.serve, path=str(tmp_path / "upstream.sock"))
    try:
        async with server, gateway(tmp_path) as client:
            responses = await asyncio.gather(*(client.post(
                f"/auth/callback?code=callback-code-canary-{index}&state=state-canary-{index}",
                headers={"X-CSRF-Token": f"csrf-canary-{index}", "X-Private-Api-Key": f"header-canary-{index}"},
                json={"id": f"failed-{index}", "fail": True}) for index in range(count)))
            assert all(response.status_code == 502 for response in responses)
        assert sorted(backend.requests) == sorted(f"failed-{index}" for index in range(count))
        raw = (tmp_path / "gateway.log").read_text()
        assert all(canary not in raw for canary in ("csrf-canary", "header-canary", "callback-code-canary", "state-canary"))
        records = [json.loads(line) for line in raw.splitlines()]
        errors = [value for value in records if value.get("logger") == "http.log.error"]
        assert len(errors) == count
        assert all(value["status"] == 502 and value["request"]["method"] == "POST" for value in errors)
        assert all("headers" not in value["request"] and "uri" not in value["request"] for value in errors)
    finally:
        server.close()
        await server.wait_closed()
        await backend.close()
