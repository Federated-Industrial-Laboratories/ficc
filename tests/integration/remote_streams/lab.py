# SPDX-License-Identifier: Apache-2.0
"""Start a real remote controller, trusted identity service and OpenSSH node."""

import contextlib
import importlib.metadata
import json
import os
import runpy
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from contributor_tls.authority import port, private, stop

from .display import Display
from .gateway import Gateway
from .identity import Identity
from .policy import Policy

SCOPES = ["nodes:read", "resources:read", "terminals:read", "terminals:execute", "terminals:stop",
          "files:read", "files:write", "workspaces:read", "workspaces:write", "modules:read",
          "modules:execute"]


class Lab:
    def __init__(self, directory, host, display=False):
        self.directory, self.host = directory, host
        self.state = directory / "state"
        self.state.mkdir(mode=0o700)
        self.process = self.log = self.admin = None
        self.socket = directory / "gateway.sock"
        secret = secrets.token_urlsafe(32)
        self.redactions = [secret]
        self.gateway = Gateway(directory, host, self.socket, port(), secret)
        self.origin = self.gateway.origin
        self.issuer = Identity(directory, self.origin + "/auth/callback")
        self.tls = ssl.create_default_context(cafile=str(self.gateway.root))
        self.tls.load_verify_locations(cafile=str(self.issuer.ca))
        private(self.state / "gateway.secret", secret)
        private(self.state / "remote.json", json.dumps({"origin": self.origin,
            "socket": str(self.socket), "gateway_secret_file": str(self.state / "gateway.secret")}))
        private(self.state / "identity-provider.json", json.dumps({"provider": "oidc",
                                                                 "configuration": self.issuer.configuration()}))
        self.ssh_directory = directory / "ssh"
        self.ssh_directory.mkdir(mode=0o700)
        values = runpy.run_path(str(host / "tests/integration/test_ssh.py"))
        self.ssh = values["ssh_fixture"].__wrapped__(self.ssh_directory)
        self.users = []
        self.display = Display(directory) if display else None
        self.policy = Policy(self) if display else None

    def start(self):
        from ficc.cli import local_request
        from ficc.local_client import client
        from ficc.settings import SCOPES as HOST_SCOPES

        if self.display:
            self.display.start()
        prior_path = os.environ.get("FICC_TEST_EXTRA_PATH")
        try:
            if self.display:
                os.environ["FICC_TEST_EXTRA_PATH"] = str(self.display.bin)
            next(self.ssh)
        finally:
            if prior_path is None:
                os.environ.pop("FICC_TEST_EXTRA_PATH", None)
            else:
                os.environ["FICC_TEST_EXTRA_PATH"] = prior_path
        self.log = (self.directory / "controller.log").open("wb")
        args = [sys.executable, "-m", "ficc.cli", "serve", "--state-dir", str(self.state),
                "--profile", "fixture-node", "--ssh-config", str(self.ssh_directory / "ssh_config")]
        if self.display:
            args += ["--viewer-runtime", os.environ["FICC_TEST_VIEWER_RUNTIME"]]
        self.process = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        for _ in range(200):
            assert self.process.poll() is None, "The remote controller exited."
            if (self.state / "control.sock").exists() and self.socket.exists():
                break
            time.sleep(0.05)
        else:
            raise AssertionError("The remote controller did not start.")
        grant = local_request(self.state, {"action": "token", "label": "Remote stream fixture",
            "lifetime": 3600, "scopes": sorted(HOST_SCOPES)})
        self.redactions.append(grant["credential"])
        self.admin = client(grant, self.state)
        self.gateway.start()
        for _ in range(100):
            if self.api("GET", "/api/v1/login")["ready"]:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("The installed identity provider did not start.")
        preview = self.api("POST", "/api/v1/node-previews", json={"profile": "fixture-node",
                                                                "name": "Remote stream node"})
        self.node = self.api("POST", "/api/v1/nodes", json={"preview_id": preview["preview_id"],
            "expected_fingerprint": preview["fingerprint"], "install_helper": True})
        self.files = self.directory / "files"
        self.files.mkdir(mode=0o700)
        self.root = local_request(self.state, {"action": "root-add", "label": "Remote stream files",
            "path": str(self.files), "node_id": None, "read_only": False})
        self.project = self.api("POST", "/api/v1/projects", json={"label": "Remote streams"})
        self.api("PUT", f"/api/v1/projects/{self.project['id']}/resources", json={
            "node_ids": [self.node["id"]], "root_ids": [self.root["id"]], "revision": 0})
        if self.display:
            self.profile = self.api("PUT", f"/api/v1/nodes/{self.node['id']}/vm-profile",
                                    json={"connection": "session", "enabled": True})
            self.policy.start()

    def api(self, method, path, **kwargs):
        response = self.admin.request(method, path, **kwargs)
        assert response.status_code in (200, 201), f"Private administration HTTP{response.status_code}."
        return response.json()

    def member(self, scopes=None):
        index = len(self.users)
        user = self.api("POST", "/api/v1/identities", json={"label": f"Remote operator {index}"})
        self.api("PUT", f"/api/v1/projects/{self.project['id']}/members/{user['id']}",
                 json={"scopes": scopes or SCOPES, "revision": 0})
        if self.policy:
            self.policy.member(user)
        mapping = self.api("PUT", "/api/v1/external-identities", json={"issuer": self.issuer.issuer,
            "external_subject": f"person-{index}", "subject_id": user["id"], "disabled": False, "revision": 0})
        self.users.append({"user": user, "mapping": mapping})
        return index

    async def login(self, index):
        transport = httpx.AsyncHTTPTransport(verify=self.tls, local_address=f"127.0.0.{index + 1}")
        client = httpx.AsyncClient(base_url=self.origin, transport=transport, trust_env=False,
                                   timeout=15, follow_redirects=False, headers={"Origin": self.origin})
        try:
            response = await client.post("/auth/start")
            assert response.status_code == 200
            self.issuer.subject_index = index
            authorization = await client.get(response.json()["url"])
            assert authorization.status_code == 303
            callback = await client.get(authorization.headers["location"])
            assert callback.status_code == 303 and callback.headers["location"] == "/"
            result = await client.get("/api/v1/session")
            assert result.status_code == 200
            value = result.json()
            assert value["remote"] and not value["principal"]["local_owner"]
            assert value["principal"]["subject_id"] == self.users[index]["user"]["id"]
            self.redactions.append(value["csrf"])
            client.headers["X-CSRF-Token"] = value["csrf"]
            return client, value
        except BaseException:
            await client.aclose()
            raise

    def revoke(self, index):
        value = self.users[index]["mapping"]
        return self.api("PUT", "/api/v1/external-identities", json={key: value[key] for key in
            ("issuer", "external_subject", "subject_id", "revision")} | {"disabled": True})

    def close(self):
        self.gateway.close()
        if self.admin:
            self.admin.close()
        if self.process:
            stop(self.process)
        if self.log:
            self.log.close()
        self.ssh.close()
        if self.display:
            self.display.close()
        self.issuer.close()
        output = os.environ.get("FICC_STREAM_LOG_DIRECTORY")
        if output:
            destination = Path(output) / self.directory.name
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            for path in [*self.directory.glob("*.log"), self.ssh_directory / "server.log"]:
                if path.exists():
                    text = path.read_bytes()[-1024 * 1024:].decode(errors="replace")
                    for value in self.redactions:
                        text = text.replace(value, "[redacted]")
                    lines = []
                    for line in text.splitlines():
                        try:
                            record = json.loads(line)
                            headers = record.get("request", {}).get("headers", {})
                            for key in headers:
                                if key.lower() in {"authorization", "proxy-authorization", "cookie",
                                                   "set-cookie", "x-csrf-token", "x-ficc-gateway"}:
                                    headers[key] = ["[redacted]"]
                            line = json.dumps(record)
                        except (ValueError, AttributeError, TypeError):
                            pass
                        lines.append(line)
                    text = "\n".join(lines) + "\n"
                    private(destination / path.name, text)


@contextlib.contextmanager
def laboratory(*, display=False):
    import ficc

    host = Path(os.environ["FICC_TEST_HOST_SOURCE"]).resolve()
    assert Path(ficc.__file__).is_relative_to(host / "src")
    entry = list(importlib.metadata.entry_points(group="ficc.identity", name="oidc"))
    assert len(entry) == 1 and "/identity-providers/" not in entry[0].load().__file__
    with tempfile.TemporaryDirectory(prefix="ficc-streams-") as name:
        directory = Path(name)
        directory.chmod(0o700)
        lab = Lab(directory, host, display)
        try:
            lab.start()
            yield lab
        finally:
            lab.close()
