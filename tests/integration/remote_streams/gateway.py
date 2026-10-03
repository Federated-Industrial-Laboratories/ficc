# SPDX-License-Identifier: Apache-2.0
"""Run the supplied browser gateway with an explicit private test CA."""

import os
import ssl
import subprocess
import time

import httpx
from contributor_tls.authority import private, stop
from contributor_tls.gateway import server_certificate


class Gateway:
    def __init__(self, directory, host, socket, port, secret):
        self.directory, self.host, self.socket = directory, host, socket
        self.port, self.secret = port, secret
        self.root, self.certificate, self.key = server_certificate(directory)
        self.tls = ssl.create_default_context(cafile=str(self.root))
        self.origin = f"https://localhost:{port}"
        self.process = self.log = None

    def start(self):
        binary = os.environ["FICC_TEST_CADDY"]
        assert "v2.11.4" in subprocess.check_output([binary, "version"], text=True, timeout=5)
        rules = (self.host / "packaging/remote/controller.caddy").read_text()
        rules = rules.replace("unix//run/ficc-controller/gateway.sock", "unix/" + str(self.socket))
        config = ("{\n admin off\n auto_https off\n servers {\n  protocols h1 h2\n }\n}\n"
                  f"{self.origin} {{\n bind 127.0.0.1\n tls {self.certificate} {self.key} {{\n"
                  "  protocols tls1.3 tls1.3\n }\n" + rules + "\n}\n")
        path = self.directory / "Caddyfile"
        private(path, config)
        self.log = (self.directory / "gateway.log").open("ab")
        env = {**os.environ, "FICC_PUBLIC_ADDRESS": f"localhost:{self.port}",
               "FICC_GATEWAY_SECRET": self.secret, "GOMAXPROCS": "2", "GOMEMLIMIT": "256MiB",
               "XDG_DATA_HOME": str(self.directory / "caddy-data"),
               "XDG_CONFIG_HOME": str(self.directory / "caddy-config")}
        self.process = subprocess.Popen([binary, "run", "--config", str(path), "--adapter", "caddyfile"],
                                        env=env, stdout=self.log, stderr=self.log)
        with httpx.Client(verify=self.tls, trust_env=False, timeout=1) as client:
            for _ in range(100):
                assert self.process.poll() is None, "The remote gateway exited."
                try:
                    if client.get(self.origin + "/api/v1/session").status_code == 401:
                        return
                except httpx.TransportError:
                    pass
                time.sleep(0.05)
        raise AssertionError("The remote gateway did not start.")

    def close(self):
        if self.process:
            stop(self.process)
            self.process = None
        if self.log:
            self.log.close()
            self.log = None
