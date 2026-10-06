# SPDX-License-Identifier: Apache-2.0
"""Exercise an installed controller through a real isolated launchd job."""

import socket
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from ficc import launcher, launcher_macos
from ficc.cli import local_request
from ficc.launcher_config import load

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="Requires native launchd")


def test_installed_controller_start_authenticate_repeat_and_stop(tmp_path, monkeypatch):
    # Keep startup files in this fixture; the job still runs in the real GUI domain.
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    path = tmp_path / "config/launcher.json"
    args = SimpleNamespace(name="ficc-ci-" + uuid.uuid4().hex[:12], launcher_config=path,
        state_dir=tmp_path / "state", port=port, profile=[], ssh_config=None,
        demo=True, autostart=False)
    launcher.install(args)
    config = load(path)
    target = launcher_macos.domain() + "/" + launcher_macos.label(config)
    try:
        assert launcher.status(path)["state"] == "stopped"
        launcher.start(path)
        assert launcher.status(path)["ready"] is True
        assert launcher.start(path) == config
        grant = local_request(Path(config.state_dir), {"action": "ephemeral"})
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False,
                              timeout=5) as client:
                assert client.get("/api/v1/session").status_code == 401
                response = client.get("/api/v1/session", headers={
                    "Authorization": "Bearer " + grant["credential"]})
                assert response.status_code == 200 and response.json()["mode"] == "demo"
                assert client.get("/").status_code == 200
        finally:
            local_request(Path(config.state_dir), {"action": "revoke", "id": grant["id"]})
        assert launcher.stop(path)["stopped"] is True
        assert launcher.status(path)["state"] == "stopped"
        assert not Path(config.state_dir, "control.sock").exists()
    finally:
        launcher_macos.launchctl("bootout", target, check=False)
        log = Path(config.state_dir, "service.log")
        if log.exists():
            print(log.read_text()[-4000:])
