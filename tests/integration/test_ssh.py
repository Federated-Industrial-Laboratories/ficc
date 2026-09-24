# SPDX-License-Identifier: Apache-2.0
"""Exercise host trust, helper installation and collection through real OpenSSH."""

import os
import pwd
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from ficc.errors import Failure
from ficc.settings import Settings, private_directory
from ficc.ssh import SSH


@pytest.fixture
def ssh_fixture(tmp_path):
    binary = os.environ.get("FICC_TEST_SSHD") or shutil.which("sshd")
    if not binary and Path("/usr/sbin/sshd").exists():
        binary = "/usr/sbin/sshd"
    if not binary:
        if os.environ.get("FICC_REQUIRE_SSH") == "1":
            pytest.fail("An OpenSSH server is required for this check.")
        pytest.skip("Set FICC_TEST_SSHD to an OpenSSH server binary.")
    for name in ("host", "client", "other"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
                        str(tmp_path / name)], check=True, capture_output=True)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    user = pwd.getpwuid(os.getuid()).pw_name
    authorized = tmp_path / "authorized_keys"
    authorized.write_bytes((tmp_path / "client.pub").read_bytes())
    authorized.chmod(0o600)
    server_config = tmp_path / "sshd_config"
    server_config.write_text("\n".join([
        f"Port {port}", "ListenAddress 127.0.0.1", f"HostKey {tmp_path / 'host'}",
        f"PidFile {tmp_path / 'pid'}", f"AuthorizedKeysFile {authorized}",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no",
        "StrictModes no", f"AllowUsers {user}", f"SetEnv HOME={home}", "LogLevel ERROR", "",
    ]))
    extra_path = os.environ.get("FICC_TEST_EXTRA_PATH")
    if extra_path:
        server_config.write_text(server_config.read_text().replace(
            f"SetEnv HOME={home}", f"SetEnv HOME={home} PATH={extra_path}:/usr/bin:/bin"))
    known = tmp_path / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} " + (tmp_path / "host.pub").read_text())
    client_config = tmp_path / "ssh_config"
    client_config.write_text("\n".join([
        "Host fixture-node", "  HostName 127.0.0.1", f"  Port {port}", f"  User {user}",
        f"  IdentityFile {tmp_path / 'client'}", "  IdentitiesOnly yes",
        f"  UserKnownHostsFile {known}", "  GlobalKnownHostsFile /dev/null", "",
    ]))
    state = tmp_path / "state"
    private_directory(state)
    log = (tmp_path / "server.log").open("wb")
    process = subprocess.Popen([binary, "-D", "-e", "-f", str(server_config)],
                               stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail((tmp_path / "server.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("The isolated SSH server did not start.")
        yield SSH(Settings(state_dir=state, profiles=("fixture-node",),
                           ssh_config=client_config, control=False)), home, tmp_path
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()


async def test_real_install_and_collect(ssh_fixture):
    transport, home, _ = ssh_fixture
    preview = await transport.preview("fixture-node", "Test machine")
    assert preview["trust"] == "trusted"
    assert preview["helper_install_required"] is True
    assert not (home / ".local/lib/ficc/node.pyz").exists()
    await transport.install(preview)
    sample = await transport.probe(preview)
    assert sample["version"] == "1"
    assert sample["resources"]["cpu_count"] > 0
    assert sample["resources"]["memory_total_bytes"] > 0
    assert len(sample["resources"]["load"]) == 3
    assert (home / ".local/lib/ficc/node.pyz").is_file()
    again = await transport.preview("fixture-node", "Test machine")
    assert again["helper_install_required"] is False


async def test_real_changed_key_refuses(ssh_fixture):
    transport, _, root = ssh_fixture
    preview = await transport.preview("fixture-node", "Test machine")
    preview["key"] = (root / "other.pub").read_text().split()[1]
    with pytest.raises(Failure) as failure:
        await transport.probe(preview)
    assert failure.value.code == "host_key_changed"


async def test_real_wrong_identity_refuses(ssh_fixture):
    transport, _, root = ssh_fixture
    preview = await transport.preview("fixture-node", "Test machine")
    config = root / "ssh_config"
    config.write_text(config.read_text().replace(str(root / "client"), str(root / "other")))
    with pytest.raises(Failure) as failure:
        await transport.probe(preview)
    assert failure.value.code == "authentication_failed"
