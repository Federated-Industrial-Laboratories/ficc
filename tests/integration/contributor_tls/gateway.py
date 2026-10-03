# SPDX-License-Identifier: Apache-2.0
"""Expose production gateway rules on private loopback TLS listeners."""

import ipaddress
import os
import re
import ssl
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .authority import private, stop


def server_certificate(directory: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local gateway root")])
    now = datetime.now(UTC)
    root = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(True, 1), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .sign(key, hashes.SHA256()))
    server_key = ec.generate_private_key(ec.SECP256R1())
    certificate = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(root.subject)
        .public_key(server_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(key, hashes.SHA256()))
    files = [directory / name for name in ("server-root.pem", "server.pem", "server.key")]
    private(files[0], root.public_bytes(serialization.Encoding.PEM))
    private(files[1], certificate.public_bytes(serialization.Encoding.PEM))
    private(files[2], server_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return files


class Gateway:
    def __init__(self, directory, host, socket, root, browser_port, node_port, secrets, server_address="localhost"):
        self.directory, self.host = directory, host
        self.socket, self.node_root = socket, root
        self.browser_port, self.node_port = browser_port, node_port
        self.server_address = server_address
        self.root, self.cert, self.key = server_certificate(directory)
        self.env = {**os.environ, "FICC_PUBLIC_ADDRESS": f"{server_address}:{browser_port}",
                    "FICC_GATEWAY_SECRET": secrets[0], "FICC_NODE_GATEWAY_SECRET": secrets[1],
                    "GOMAXPROCS": "2", "XDG_DATA_HOME": str(directory / "caddy-data"),
                    "XDG_CONFIG_HOME": str(directory / "caddy-config")}
        self.process = None
        self.output = None
        self.tls = ssl.create_default_context(cafile=str(self.root))

    def start(self, *, polling_only=False):
        binary = os.environ["FICC_TEST_CADDY"]
        assert "v2.11.4" in subprocess.check_output([binary, "version"], text=True)
        browser = (self.host / "packaging/remote/controller.caddy").read_text()
        node = (self.host / "packaging/remote/contributors.caddy").read_text()
        browser = browser.replace("unix//run/ficc-controller/gateway.sock", "unix/" + str(self.socket))
        node = node.replace("https://{$FICC_PUBLIC_ADDRESS}:8443 {\n",
            f"https://{self.server_address}:{self.node_port} {{\n\tbind 127.0.0.1\n")
        node = node.replace("https://:8443 {\n", f"https://:{self.node_port} {{\n\tbind 127.0.0.1\n")
        node = node.replace("\ttls {", f"\ttls {self.cert} {self.key} {{")
        node = node.replace("\t\tissuer acme {$FICC_ACME_DIRECTORY} {\n\t\t\tprofile shortlived\n\t\t}\n", "")
        node = node.replace("/etc/ficc-gateway/node-ca.pem", str(self.node_root))
        node = node.replace("unix//run/ficc-controller/gateway.sock", "unix/" + str(self.socket))
        if polling_only:
            node = node.replace("\t@node path", "\thandle /api/v1/node-channel/stream {\n"
                                "\t\trespond 503\n\t}\n\t@node path")
        options = (self.host / "packaging/remote/Caddyfile").read_text()
        selected = re.search(r"\tservers :8443 \{\n.*?\n\t\}", options, re.S)
        assert selected is not None, "The contributor listener requires its supplied server options."
        scoped = selected.group().replace(":8443", f"127.0.0.1:{self.node_port}")
        value = ("{\n admin off\n auto_https off\n servers {\n  protocols h1 h2\n }\n"
            f" default_sni {self.server_address}\n{scoped}\n}}\n"
            f"https://{self.server_address}:{self.browser_port} {{\n bind 127.0.0.1\n tls {self.cert} {self.key} {{\n"
            "  protocols tls1.3 tls1.3\n }\n" + browser + "\n}\n" + node)
        path = self.directory / "Caddyfile"
        private(path, value)
        self.output = (self.directory / "gateway.log").open("ab")
        self.process = subprocess.Popen([binary, "run", "--config", str(path), "--adapter", "caddyfile"],
            env=self.env, stdout=self.output, stderr=self.output)
        with httpx.Client(verify=self.tls, trust_env=False, timeout=1) as client:
            for _ in range(100):
                assert self.process.poll() is None, "The TLS gateway exited."
                try:
                    response = client.get(f"https://{self.server_address}:{self.browser_port}/api/v1/contributors")
                    if response.status_code in (401, 403):
                        return
                except httpx.TransportError:
                    pass
                time.sleep(0.05)
        raise AssertionError("The TLS gateway did not start.")

    def close(self):
        if self.process is not None:
            stop(self.process)
            self.process = None
        if self.output is not None:
            self.output.close()
            self.output = None
