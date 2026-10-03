# SPDX-License-Identifier: Apache-2.0
"""Require authenticated node TLS with IP addresses and across fallback policies."""

import asyncio
import json
import socket
import ssl
import subprocess

import httpx
import pytest
from contributor_tls.lab import laboratory, poll, running
from test_contributor_tls_security import wrong_client


def exchange(context, port, server_name, host, *, session=None, method="POST"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=server_name, session=session) as tls:
            tls.settimeout(5)
            path = "/api/v1/contributors" if method == "GET" else "/api/v1/node-channel/activate"
            request = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
                       "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
            tls.sendall(request.encode())
            data = bytearray()
            while True:
                part = tls.recv(4096)
                if not part:
                    break
                data.extend(part)
                assert len(data) < 32768
            return int(data.split(b" ", 2)[1]), tls.session, tls.session_reused


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_ip_nodes_and_every_fallback_policy_require_current_verified_identity(count):
    with laboratory(server_address="127.0.0.1") as lab:
        states = await lab.cohort(count)
        gateway = lab.gateway
        config = subprocess.check_output([gateway.env["FICC_TEST_CADDY"], "adapt", "--config",
            str(lab.directory / "Caddyfile"), "--adapter", "caddyfile"], env=gateway.env,
            stderr=subprocess.DEVNULL)
        servers = json.loads(config)["apps"]["http"]["servers"].values()
        node = next(server for server in servers if f"127.0.0.1:{gateway.node_port}" in server["listen"])
        assert node["strict_sni_host"] is False
        assert all(policy["client_authentication"]["mode"] == "require_and_verify"
                   for policy in node["tls_connection_policies"])
        async with running(states, "persistent"):
            await lab.connected(states, transport="persistent")
            for state in states:
                response = await poll(state, headers={"X-FICC-Node-Fingerprint": "0" * 64})
                assert response.status_code == 200
                assert response.json()["node_id"] == state.load()["node_id"]
            target = states[-1]
            value = target.load()
            verified = target.tls(value, value["current"])
            async with httpx.AsyncClient(verify=verified, trust_env=False, timeout=5) as client:
                response = await client.post(lab.node_origin + "/api/v1/node-channel/activate",
                                              headers={"Host": "unapproved.example"}, json={})
                assert response.status_code == 421
            plain = ssl.create_default_context(cafile=str(gateway.root))
            plain.minimum_version = ssl.TLSVersion.TLSv1_3
            wrong = ssl.create_default_context(cafile=str(gateway.root))
            wrong.load_cert_chain(*wrong_client(lab.directory))
            host = f"127.0.0.1:{gateway.node_port}"
            for context in (plain, wrong):
                for sni in ("127.0.0.1", "localhost"):
                    with pytest.raises(ssl.SSLError):
                        await asyncio.to_thread(exchange, context, gateway.node_port, sni, host)
            status, ticket, _ = await asyncio.to_thread(exchange, plain, gateway.browser_port,
                "127.0.0.1", f"127.0.0.1:{gateway.browser_port}", method="GET")
            assert status == 401 and ticket.has_ticket
            with pytest.raises(ssl.SSLError):
                await asyncio.to_thread(exchange, plain, gateway.node_port, "127.0.0.1", host,
                                        session=ticket)
            assert (await poll(target)).status_code == 200
