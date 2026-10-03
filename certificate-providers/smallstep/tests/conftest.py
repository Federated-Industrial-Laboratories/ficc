# SPDX-License-Identifier: Apache-2.0
"""Start a private, pinned Smallstep authority for certificate checks."""

import importlib.util
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
from joserfc.jwk import ECKey

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ficc_certificates_smallstep import create


def write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def authority(tmp_path_factory):
    directory = tmp_path_factory.mktemp("node-ca")
    directory.chmod(0o700)
    home = directory / "online"
    home.mkdir(mode=0o700)
    offline = directory / "offline"
    offline.mkdir(mode=0o700)
    password = directory / "password"
    write_private(password, secrets.token_urlsafe(32).encode())
    step = os.environ["FICC_TEST_STEP"]
    server = os.environ["FICC_TEST_STEP_CA"]
    assert "0.31.0" in subprocess.check_output([step, "version"], text=True)
    assert "0.30.2" in subprocess.check_output([server, "version"], text=True)
    env = {**os.environ, "STEPPATH": str(home), "GOMAXPROCS": "2"}
    port = free_port()
    command = [step, "ca", "init", "--deployment-type=standalone", "--name=Node Test CA",
               "--dns=localhost", "--dns=127.0.0.1", f"--address=127.0.0.1:{port}",
               "--provisioner=bootstrap", "--password-file", str(password)]
    result = subprocess.run(command, env=env, capture_output=True, timeout=30)
    assert result.returncode == 0, "The private CA initialization failed."
    (home / "secrets/root_ca_key").rename(offline / "root_ca_key")
    assert not (home / "secrets/root_ca_key").exists()
    key = ECKey.generate_key("P-256", parameters={"alg": "ES256", "use": "sig"})
    key.ensure_kid()
    signing = directory / "provisioner.json"
    write_private(signing, json.dumps(key.as_dict(private=True)).encode())
    installation = secrets.token_hex(16)
    filename = Path(__file__).parents[1] / "deployment/profile.py"
    spec = importlib.util.spec_from_file_location("ca_profile", filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profile = module.profile(home, key.as_dict(private=False), installation, port)
    write_private(home / "config/ca.json", json.dumps(profile).encode())
    log = directory / "server.log"
    with log.open("wb") as output:
        log.chmod(0o600)
        process = subprocess.Popen([server, str(home / "config/ca.json"), "--password-file",
                                    str(password)], env=env, stdout=output, stderr=output)
        root = home / "certs/root_ca.crt"
        root.chmod(0o600)
        tls = ssl.create_default_context(cafile=str(root))
        config = {"ca_url": f"https://localhost:{port}", "installation_id": installation,
                  "provisioner": "ficc-nodes", "signing_key_file": str(signing),
                  "root_file": str(root), "request_seconds": 10}
        client = httpx.Client(verify=tls, trust_env=False, timeout=2)
        try:
            for _ in range(100):
                assert process.poll() is None, "The private authority exited."
                try:
                    if client.get(config["ca_url"] + "/health").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.05)
            else:
                pytest.fail("The private authority did not start.")
            yield SimpleNamespace(config=config, key=key, directory=directory, home=home,
                                  tls=tls, client=client, process=process, installation=installation)
        finally:
            client.close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        assert b'"ott"' not in log.read_bytes() and b"eyJhbGci" not in log.read_bytes()


@pytest.fixture
def provider(authority):
    result = create(authority.config)
    try:
        yield result
    finally:
        result.close()


def node(installation: str, *, index: int = 0, key=None, sans=None, subject=None,
         extra=None, seconds: int = 3600):
    node_id = secrets.token_hex(16)
    key = key or (ed25519.Ed25519PrivateKey.generate() if index % 2
                  else ec.generate_private_key(ec.SECP256R1()))
    uri = f"urn:ficc:node:{installation}:{node_id}"
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        subject or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
    builder = builder.add_extension(x509.SubjectAlternativeName(
        sans if sans is not None else [x509.UniformResourceIdentifier(uri)]), critical=False)
    if extra is not None:
        builder = builder.add_extension(extra, critical=True)
    csr = builder.sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256())
    return ({"request_id": secrets.token_hex(16), "node_id": node_id, "identity_uri": uri,
             "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
             "validity_seconds": seconds}, key)


def cohort(authority, count):
    rows = [node(authority.installation, index=index) for index in range(count)]
    assert len({row[0]["node_id"] for row in rows}) == count
    return rows


def leaf(result):
    return x509.load_pem_x509_certificates(result["certificate_chain"].encode())[0]


def crl(authority):
    response = authority.client.get(authority.config["ca_url"] + "/crl")
    assert response.status_code == 200
    result = x509.load_der_x509_crl(response.content)
    intermediate = x509.load_pem_x509_certificate(
        (authority.home / "certs/intermediate_ca.crt").read_bytes())
    assert result.is_signature_valid(intermediate.public_key())
    return {entry.serial_number for entry in result}
