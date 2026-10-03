# SPDX-License-Identifier: Apache-2.0
"""Run isolated certificate-only SSH servers without changing host services."""

import importlib.util
import os
import pwd
import shutil
import socket
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("ssh_certificate_material",
    Path(__file__).parents[1] / "python/test_ssh_trust_support.py")
material = importlib.util.module_from_spec(spec)
spec.loader.exec_module(material)


def binary():
    value = os.environ.get("FICC_TEST_SSHD") or shutil.which("sshd")
    if value is None and Path("/usr/sbin/sshd").exists():
        value = "/usr/sbin/sshd"
    if value is None:
        if os.environ.get("FICC_REQUIRE_SSH") == "1":
            pytest.fail("An OpenSSH server is required for this check.")
        pytest.skip("Set FICC_TEST_SSHD to an OpenSSH server binary.")
    return value


@contextmanager
def server(root, row, *, certificate=None):
    executable = binary()
    location = root / row["node"]["profile"]
    location.mkdir(mode=0o700, exist_ok=True)
    home = location / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    user = pwd.getpwuid(os.getuid()).pw_name
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    index = row["node"]["profile"].split("-")[-1]
    assets = root / "certificates"
    principal = material.save(location / "principals", row["node"]["account"].encode())
    config = location / "sshd_config"
    config.write_text("\n".join([
        f"Port {port}", "ListenAddress 127.0.0.1", f"HostKey {assets / ('host-' + index)}",
        f"HostCertificate {certificate or row['host_certificate']}", f"PidFile {location / 'pid'}",
        "AuthorizedKeysFile /dev/null", f"TrustedUserCAKeys {assets / 'ca.pub'}",
        f"AuthorizedPrincipalsFile {principal}", f"RevokedKeys {assets / 'revoked.krl'}",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no",
        "StrictModes no", f"AllowUsers {user}", f"SetEnv HOME={home}", "LogLevel DEBUG3", "",
    ]))
    client = root / "ssh_config"
    previous = client.read_text() if client.exists() else ""
    with client.open("a") as stream:
        stream.write("\n".join([
            f"Host {row['node']['profile']}", "  HostName 127.0.0.1", f"  Port {port}", f"  User {user}",
            f"  IdentityFile {assets / ('client-' + index)}", "  IdentitiesOnly yes", "",
        ]))
    log = (location / "sshd.log").open("wb")
    process = subprocess.Popen([executable, "-D", "-e", "-f", str(config)],
                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail((location / "sshd.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            pytest.fail("The isolated SSH certificate server did not start.")
        yield home
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()
        client.write_text(previous)
