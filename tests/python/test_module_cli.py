# SPDX-License-Identifier: Apache-2.0
"""Check package CLI workflows against a real private service and credential socket."""

import hashlib
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time

import httpx
import pytest
from test_modules_packages import bundle, package

from ficc.cli import local_request, main
from ficc.module_cli import read_file


@pytest.fixture
def module_service(tmp_path):
    state = tmp_path / "state"
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
    log = (tmp_path / "service.log").open("wb")
    process = subprocess.Popen([sys.executable, "-m", "ficc.cli", "serve", "--state-dir", str(state),
                                "--port", str(port)], stdout=log, stderr=log, start_new_session=True)
    try:
        deadline = time.monotonic() + 15
        while not (state / "control.sock").exists():
            if process.poll() is not None or time.monotonic() > deadline:
                pytest.fail("The isolated service did not start")
            time.sleep(.05)
        yield state
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        log.close()


def cli(capsys, state, name, *args, code=0):
    status = main(["module-" + name, "--state-dir", str(state), *map(str, args)])
    output = capsys.readouterr()
    assert status == code, output.err
    with sqlite3.connect(state / "state.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM credentials WHERE label='Local CLI'").fetchone()[0] == 0
    if code:
        assert not output.out
        return output.err
    return json.loads(output.out)


@pytest.mark.parametrize("count", [1, 64])
def test_cli_preview_cleanup_install_grant_disable_and_remove(module_service, tmp_path, capsys, count):
    state = module_service
    source = tmp_path / "clock.ficc-module"
    source.write_bytes(bundle(*package(capabilities=["workspace:read"])))
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    for _ in range(count):
        inspected = cli(capsys, state, "inspect", "--file", source)
        assert inspected["digest"] == checksum and "preview_id" not in inspected
    error = cli(capsys, state, "install", "--file", source, "--expected-digest", "0" * 64,
                "--accept-unverified", code=1)
    assert "does not match" in error
    assert cli(capsys, state, "list")["modules"] == []
    installed = cli(capsys, state, "install", "--file", source, "--expected-digest", checksum,
                    "--accept-unverified")
    assert not installed["enabled"]
    owner = local_request(state, {"action": "ephemeral"})
    try:
        with httpx.Client(base_url=owner["origin"], trust_env=False,
                          headers={"Authorization": "Bearer " + owner["credential"]}) as client:
            spaces = [client.post("/api/v1/workspaces", json={"name": f"Workspace {i}"}).json()
                      for i in range(count)]
    finally:
        local_request(state, {"action": "revoke", "id": owner["id"]})
    grants = tmp_path / "grants.json"
    grants.write_text(json.dumps([{"capability": "workspace:read", "target_ids": [s["id"] for s in spaces]}]))
    assert cli(capsys, state, "enable", checksum, "--grants", grants)["enabled"]
    assert not cli(capsys, state, "disable", checksum)["enabled"]
    assert cli(capsys, state, "remove", checksum, "--confirm") == {"removed": True}
    assert cli(capsys, state, "list")["modules"] == []


def test_cli_api_refusal_is_actionable_and_revokes_credential(module_service, capsys):
    message = cli(capsys, module_service, "inspect", "--url", "http://127.0.0.1/pkg", code=1)
    assert "HTTP" in message and "Bearer" not in message


def test_preview_release_is_bound_to_current_owner(console):
    client, service = console
    data = bundle(*package())
    previews = [client.post("/api/v1/module-install-previews", content=data).json() for _ in range(4)]
    assert client.post("/api/v1/module-install-previews", content=data).status_code == 429
    token, _ = service.auth.issue("token", "Other owner")
    url = "/api/v1/module-install-previews/" + previews[0]["preview_id"]
    assert client.delete(url, headers={"Authorization": "Bearer " + token}).status_code == 200
    assert client.post("/api/v1/module-install-previews", content=data).status_code == 429
    assert client.delete(url).status_code == 200
    assert client.post("/api/v1/module-install-previews", content=data).status_code == 200


@pytest.mark.parametrize("kind", ["link", "fifo", "directory", "oversize"])
def test_cli_refuses_unsafe_or_unbounded_local_inputs(tmp_path, kind):
    path = tmp_path / "input"
    if kind == "link":
        path.symlink_to(__file__)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"a" * 65)
    with pytest.raises((OSError, ValueError)):
        read_file(path, 64)


def test_cli_requires_exact_digest_and_explicit_source_acceptance(tmp_path):
    with pytest.raises(SystemExit) as error:
        main(["module-install", "--file", str(tmp_path / "not-opened"), "--expected-digest", "0" * 64])
    assert error.value.code == 2
    with pytest.raises(SystemExit) as error:
        main(["module-remove", "../../elsewhere", "--confirm"])
    assert error.value.code == 2
