# SPDX-License-Identifier: Apache-2.0
"""Exercise owner recovery over real private control and HTTP Unix sockets."""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest
from remote_fixtures import ISSUER, ORIGIN, configure

from ficc.cli import local_request, main
from ficc.local_client import client


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_remote_server_keeps_owner_cli_local_without_identity_service(count, capsys):
    with tempfile.TemporaryDirectory(prefix="ficc-remote-control-") as directory:
        folder = Path(directory)
        state = folder / "state"
        configure(state)
        (state / "identity-provider.json").unlink()
        with socket.socket() as reserved, (folder / "server.log").open("w+") as log:
            reserved.bind(("127.0.0.1", 0))
            reserved.listen(1)
            process = subprocess.Popen([sys.executable, "-m", "ficc.cli", "serve", "--state-dir", str(state),
                                        "--port", str(reserved.getsockname()[1])], stdout=log, stderr=log,
                                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            try:
                deadline = time.monotonic() + 30
                while not (state / "control.sock").exists():
                    assert process.poll() is None, "The isolated remote controller failed to start."
                    assert time.monotonic() < deadline, "The private owner socket did not start."
                    time.sleep(0.05)
                gateway = folder / "gateway.sock"
                assert gateway.stat().st_mode & 0o777 == 0o660
                assert (state / "control.sock").stat().st_mode & 0o777 == 0o600
                with httpx.Client(transport=httpx.HTTPTransport(uds=str(gateway)), base_url="http://controller.example") as untrusted:
                    assert untrusted.get("/api/v1/login").status_code == 403
                for index in range(count):
                    user = local_request(state, {"action": "identity-create", "label": f"Recovery member {index}"})
                    local_request(state, {"action": "identity-external-set", "issuer": ISSUER,
                                         "external_subject": f"remote-{index}", "subject": user["id"],
                                         "disabled": False, "revision": 0})
                    assert main(["nodes", "--state-dir", str(state)]) == 0
                    assert json.loads(capsys.readouterr().out)["nodes"] == []
                grant = local_request(state, {"action": "ephemeral"})
                try:
                    with client(grant, state) as owner:
                        response = owner.get("/api/v1/external-identities")
                        assert response.status_code == 200, response.text
                        value = response.json()
                        assert len(value["mappings"]) == count
                        assert value["provider"] == {"remote": True, "configured": False, "ready": False,
                                                     "verification_seconds": 30, "issuer": None}
                        assert owner.get("/api/v1/login").headers["strict-transport-security"]
                    with pytest.raises(ValueError, match="origin changed"):
                        client({**grant, "origin": ORIGIN + ":8443"}, state)
                finally:
                    local_request(state, {"action": "revoke", "id": grant["id"]})
                assert main(["policy-list", "--state-dir", str(state)]) == 0
                assert json.loads(capsys.readouterr().out)["packages"] == []
            finally:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            assert process.returncode in {0, -signal.SIGTERM}
            assert not gateway.exists() and not (state / "control.sock").exists()
