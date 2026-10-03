# SPDX-License-Identifier: Apache-2.0
"""Join real node clients to a separate controller and trusted TLS gateway."""

import asyncio
import contextlib
import importlib.metadata
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from .authority import authority, port, private, stop
from .gateway import Gateway


class Lab:
    def __init__(self, directory, host, provider, root, certificate_seconds=3600, server_address="localhost"):
        self.directory, self.host = directory, host
        self.provider_configuration = provider
        self.state = directory / "controller"
        self.state.mkdir(mode=0o700)
        self.nodes = []
        self.gateway_socket = directory / "gateway.sock"
        browser_port, node_port = port(), port()
        self.browser_origin, self.node_origin = (f"https://{server_address}:{browser_port}",
                                                 f"https://{server_address}:{node_port}")
        credentials = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.redactions = list(credentials)
        private(self.state / "gateway.secret", credentials[0])
        private(self.state / "node-gateway.secret", credentials[1])
        private(self.state / "remote.json", json.dumps({"origin": self.browser_origin,
            "socket": str(self.gateway_socket), "gateway_secret_file": str(self.state / "gateway.secret")}))
        private(self.state / "contributors.json", json.dumps({
            "deployment_id": provider["installation_id"], "origin": self.node_origin,
            "ca_file": str(root), "gateway_secret_file": str(self.state / "node-gateway.secret"),
            "issuer": {"provider": "smallstep", "configuration": provider},
            "limits": {"certificate_seconds": certificate_seconds, "invitation_seconds": 900,
                       "lease_seconds": 5, "heartbeat_seconds": 1, "max_nodes": 64}}))
        self.gateway = Gateway(directory, host, self.gateway_socket, root, browser_port, node_port,
                               credentials, server_address)
        self.process = None
        self.output = None
        self.admin = None

    def start(self):
        from ficc.cli import local_request
        from ficc.local_client import client

        self.output = (self.directory / "controller.log").open("wb")
        self.process = subprocess.Popen([sys.executable, "-m", "ficc.cli", "serve", "--state-dir",
            str(self.state), "--port", str(port())], stdout=self.output, stderr=self.output,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        for _ in range(200):
            assert self.process.poll() is None, "The isolated controller exited."
            if (self.state / "control.sock").exists() and self.gateway_socket.exists():
                break
            time.sleep(0.05)
        else:
            raise AssertionError("The private controller did not start.")
        grant = local_request(self.state, {"action": "token", "label": "TLS integration",
            "lifetime": 3600, "scopes": ["contributors:read", "contributors:manage"]})
        self.redactions.append(grant["credential"])
        self.admin = client(grant, self.state)
        for _ in range(100):
            response = self.admin.get("/api/v1/contributors")
            if response.status_code == 200 and response.json().get("issuer_ready"):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("The installed certificate provider did not start.")
        self.gateway.start()

    def api(self, method, path, **kwargs):
        response = self.admin.request(method, path, **kwargs)
        assert response.status_code in (200, 201), f"Administrative HTTP status {response.status_code}."
        return response.json()

    def listing(self):
        return {row["id"]: row for row in self.api("GET", "/api/v1/contributors")["contributors"]}

    async def enroll(self, index=0):
        from ficc import contributor_client
        from ficc.contributor_client_state import NodeState

        invitation = self.api("POST", "/api/v1/contributor-invitations",
                              json={"name": f"TLS node {index}", "mode": "voluntary"})
        path = self.directory / ("node-" + invitation["node_id"])
        state = NodeState(path)
        private(path / "invitation.json", json.dumps(invitation))
        result = await contributor_client.join(state, path / "invitation.json", self.gateway.root)
        assert result["node_id"] == invitation["node_id"] and result["status"] == "awaiting_approval"
        value = state.load()
        pending = self.listing()[value["node_id"]]["requests"]
        assert len(pending) == 1 and pending[0]["public_key"] == result["public_key"]
        before = await contributor_client.run(state, "polling", once=True)
        assert before["status"] == "awaiting_approval"
        self.api("POST", f"/api/v1/contributor-requests/{value['request_id']}/approve",
                 json={"revision": pending[0]["revision"], "public_key": result["public_key"]})
        assert await contributor_client.complete_enrollment(state, value)
        assert state.load()["stage"] == "active"
        self.nodes.append(state)
        return state

    async def cohort(self, count):
        rows = [await self.enroll(index) for index in range(count)]
        values = [state.load() for state in rows]
        assert len({value["node_id"] for value in values}) == count
        assert len({value["current"]["public_key"] for value in values}) == count
        assert len({value["current"]["fingerprint"] for value in values}) == count
        return rows

    def disable(self, state):
        identity = state.load()["node_id"]
        value = self.listing()[identity]
        return self.api("POST", f"/api/v1/contributors/{identity}/disable",
                         json={"revision": value["revision"]})

    def report(self, state):
        try:
            return json.loads((state.path / "connection.json").read_text())
        except FileNotFoundError:
            return {}

    async def connected(self, states, *, timeout=15, transport=None):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            reports = [self.report(state) for state in states]
            if all(row.get("status") == "connected" and row.get("lease_seconds", 0) > 0
                   and (transport is None or row.get("transport") == transport) for row in reports):
                return reports
            await asyncio.sleep(0.05)
        reports = [self.report(state) for state in states]
        connected = sum(row.get("status") == "connected" for row in reports)
        transports = sorted({row.get("transport", "none") for row in reports})
        raise AssertionError(f"Only {connected} of {len(states)} nodes connected; transports={transports}.")

    def close(self):
        self.gateway.close()
        if self.admin:
            self.admin.close()
        if self.process:
            stop(self.process)
        if self.output:
            self.output.close()
        destination = os.environ.get("FICC_TLS_LOG_DIRECTORY")
        if destination:
            target = Path(destination) / self.directory.name
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            for path in self.directory.glob("*.log"):
                content = path.read_bytes()[-1024 * 1024:].decode(errors="replace")
                for value in self.redactions:
                    content = content.replace(value, "[redacted]")
                private(target / path.name, content)


@contextlib.contextmanager
def laboratory(*, certificate_seconds=3600, server_address="localhost"):
    import pytest

    import ficc

    required = ("FICC_TEST_HOST_SOURCE", "FICC_TEST_CERTIFICATE_SOURCE",
                "FICC_TEST_STEP", "FICC_TEST_STEP_CA", "FICC_TEST_CADDY")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        pytest.skip("Select the contributor TLS fixtures: " + ", ".join(missing))
    host = Path(os.environ["FICC_TEST_HOST_SOURCE"]).resolve()
    assert Path(ficc.__file__).is_relative_to(host / "src")
    entry = list(importlib.metadata.entry_points(group="ficc.certificates", name="smallstep"))
    assert len(entry) == 1 and entry[0].load().API_VERSION == 1
    assert "/certificate-providers/" not in str(Path(entry[0].load().__file__))
    with tempfile.TemporaryDirectory(prefix="ficc-tls-") as name:
        directory = Path(name)
        directory.chmod(0o700)
        with authority(directory, secrets.token_hex(16)) as (provider, root):
            lab = Lab(directory, host, provider, root, certificate_seconds, server_address)
            try:
                lab.start()
                yield lab
            finally:
                lab.close()


@contextlib.asynccontextmanager
async def running(states, transport="auto"):
    from ficc.contributor_client import run

    tasks = [asyncio.create_task(run(state, transport)) for state in states]
    try:
        yield tasks
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def poll(state, *, body=None, headers=None, material=None):
    from ficc_node.collect import collect

    value = state.load()
    message = body or {"version": 1, "session_id": None, "sequence": 1,
                       "sample": await asyncio.to_thread(collect)}
    async with httpx.AsyncClient(verify=state.tls(value, material or value["current"]),
                                 trust_env=False, timeout=5) as client:
        return await client.post(value["node_origin"] + "/api/v1/node-channel/poll",
                                 json=message, headers=headers or {})


def retain_material(state):
    material = state.load()["current"].copy()
    for field in ("key_file", "certificate_file"):
        name = "retained-" + material[field]
        private(state.file(name), state.file(material[field]).read_bytes())
        material[field] = name
    return material


async def unregistered_material(lab, state):
    value = state.load()
    material = retain_material(state)
    entry = next(iter(importlib.metadata.entry_points(group="ficc.certificates", name="smallstep")))
    provider = entry.load().create(lab.provider_configuration)
    try:
        result = await asyncio.to_thread(provider.issue, {
            "request_id": secrets.token_hex(16), "node_id": value["node_id"],
            "identity_uri": f"urn:ficc:node:{value['deployment_id']}:{value['node_id']}",
            "csr_pem": material["csr_pem"], "validity_seconds": 3600})
    finally:
        await asyncio.to_thread(provider.close)
    material["certificate_file"] = "unregistered-certificate.pem"
    private(state.file(material["certificate_file"]), result["certificate_chain"])
    return material
