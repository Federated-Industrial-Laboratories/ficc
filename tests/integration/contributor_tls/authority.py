# SPDX-License-Identifier: Apache-2.0
"""Run a disposable Smallstep authority with an offline test root."""

import contextlib
import json
import os
import runpy
import secrets
import socket
import ssl
import subprocess
import time
from pathlib import Path

import httpx
from joserfc.jwk import ECKey


def private(path: Path, value: bytes | str) -> None:
    path.write_bytes(value.encode() if isinstance(value, str) else value)
    path.chmod(0o600)


def port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(process) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@contextlib.contextmanager
def authority(directory: Path, installation: str):
    home = directory / "authority"
    home.mkdir(mode=0o700)
    offline = directory / "offline"
    offline.mkdir(mode=0o700)
    password = directory / "authority-password"
    private(password, secrets.token_urlsafe(32))
    step, server = os.environ["FICC_TEST_STEP"], os.environ["FICC_TEST_STEP_CA"]
    assert "0.31.0" in subprocess.check_output([step, "version"], text=True)
    assert "0.30.2" in subprocess.check_output([server, "version"], text=True)
    env = {**os.environ, "STEPPATH": str(home), "GOMAXPROCS": "2"}
    listen = port()
    result = subprocess.run([step, "ca", "init", "--deployment-type=standalone",
        "--name=Contributor Test CA", "--dns=localhost", "--dns=127.0.0.1",
        f"--address=127.0.0.1:{listen}", "--provisioner=bootstrap",
        "--password-file", str(password)], env=env, capture_output=True, timeout=30)
    assert result.returncode == 0, "Authority setup failed."
    (home / "secrets/root_ca_key").rename(offline / "root_ca_key")
    signing = ECKey.generate_key("P-256", parameters={"alg": "ES256", "use": "sig"})
    signing.ensure_kid()
    key = directory / "provisioner.json"
    private(key, json.dumps(signing.as_dict(private=True)))
    profile = Path(os.environ["FICC_TEST_CERTIFICATE_SOURCE"]) / "deployment/profile.py"
    value = runpy.run_path(str(profile))["profile"](home, signing.as_dict(private=False),
                                                    installation, listen)
    private(home / "config/ca.json", json.dumps(value))
    root = home / "certs/root_ca.crt"
    root.chmod(0o600)
    configuration = {"ca_url": f"https://localhost:{listen}", "installation_id": installation,
        "provisioner": "ficc-nodes", "signing_key_file": str(key), "root_file": str(root),
        "request_seconds": 10}
    log = directory / "authority.log"
    with log.open("wb") as output:
        log.chmod(0o600)
        process = subprocess.Popen([server, str(home / "config/ca.json"), "--password-file",
                                    str(password)], env=env, stdout=output, stderr=output)
        try:
            tls = ssl.create_default_context(cafile=str(root))
            with httpx.Client(verify=tls, trust_env=False, timeout=1) as client:
                for _ in range(100):
                    assert process.poll() is None, "The authority exited."
                    try:
                        if client.get(configuration["ca_url"] + "/health").status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    time.sleep(0.05)
                else:
                    raise AssertionError("The authority did not start.")
            yield configuration, root
        finally:
            stop(process)
    assert b'"ott"' not in log.read_bytes() and b"eyJhbGci" not in log.read_bytes()
