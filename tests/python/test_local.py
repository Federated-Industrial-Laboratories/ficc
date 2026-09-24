# SPDX-License-Identifier: Apache-2.0
"""Check local socket access, helper output, and process bounds."""

import asyncio
import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

from ficc.api import create_app
from ficc.cli import local_request, main
from ficc.errors import Failure
from ficc.process import run
from ficc.schema import Sample
from ficc.settings import Settings
from ficc.ssh import archive
from ficc.store import Store


def test_local_socket_and_cli_workflow(tmp_path, capsys):
    state = tmp_path / "state"
    app = create_app(Settings(state_dir=state, demo=True))
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        assert (state / "control.sock").stat().st_mode & 0o777 == 0o600
        grant = local_request(state, {"action": "bootstrap"})
        login = client.post("/api/v1/session", json={"bootstrap": grant["credential"]},
                            headers={"Origin": "http://127.0.0.1:8170"})
        assert login.status_code == 200 and login.json()["mode"] == "demo"
        path = tmp_path / "token"
        assert main(["token-create", "--state-dir", str(state), "--label", "Example",
                     "--scope", "nodes:read", "--output", str(path)]) == 0
        record = json.loads(capsys.readouterr().out)
        token = path.read_text().strip()
        assert path.stat().st_mode & 0o777 == 0o600
        assert client.get("/api/v1/nodes", headers={"Authorization": "Bearer " + token}).status_code == 200
        assert main(["token-revoke", "--state-dir", str(state), record["id"]]) == 0
        assert client.get("/api/v1/nodes", headers={"Authorization": "Bearer " + token}).status_code == 401
    assert not (state / "control.sock").exists()


def test_demo_disables_live_mutations(console, tmp_path):
    app = create_app(Settings(state_dir=tmp_path / "demo", demo=True, control=False))
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        token, _ = app.state.service.auth.issue("token")
        client.headers["Authorization"] = "Bearer " + token
        assert len(client.get("/api/v1/nodes").json()["nodes"]) == 3
        result = client.post("/api/v1/nodes/refresh", json={"node_ids": ["demo-1"]})
        assert result.status_code == 403 and result.json()["error"]["code"] == "demo_read_only"


def test_private_state_and_schema_refusal(tmp_path):
    state = tmp_path / "public"
    state.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="0700"):
        Store(state / "state.sqlite3")
    private = tmp_path / "private"
    store = Store(private / "state.sqlite3")
    assert (private / "state.sqlite3").stat().st_mode & 0o777 == 0o600
    store.db.execute("PRAGMA user_version=999")
    store.close()
    with pytest.raises(ValueError, match="schema"):
        Store(private / "state.sqlite3")


def test_bounded_child_output_and_timeout():
    with pytest.raises(Failure, match="exceeds"):
        asyncio.run(run([sys.executable, "-c", "print('x'*10000)"], maximum=1024))
    with pytest.raises(Failure, match="timed out"):
        asyncio.run(run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.03))


def test_real_local_helper_archive(tmp_path):
    path = tmp_path / "node.pyz"
    path.write_bytes(archive())
    code, stdout, _ = asyncio.run(run([sys.executable, str(path)], b'{"version":"1","action":"resources"}\n'))
    assert code == 0
    value = Sample.model_validate_json(stdout)
    assert value.resources.cpu_count == os.cpu_count()
    assert value.resources.memory_total_bytes > 0
    assert value.resources.uptime_seconds > 0


def test_cli_revokes_ephemeral_token_after_api_failure(tmp_path, monkeypatch):
    import argparse

    import httpx

    import ficc.cli as cli

    actions = []

    def local_request(state, request):
        actions.append(request["action"])
        return {"origin": "http://127.0.0.1:8170", "credential": "private-token", "id": "example"}

    def failed_get(client, path):
        raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(cli, "local_request", local_request)
    monkeypatch.setattr(httpx.Client, "get", failed_get)
    with pytest.raises(httpx.ConnectError):
        cli.api_command(argparse.Namespace(state_dir=tmp_path, command="nodes"))
    assert actions == ["ephemeral", "revoke"]


def test_socket_recovery_and_single_service_lock(tmp_path):
    import socket

    from ficc.control import Control
    from ficc.service import Service

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    with socket.socket(socket.AF_UNIX) as stale:
        stale.bind(str(state / "control.sock"))

    async def check():
        first_service = Service(Settings(state_dir=state))
        second_service = Service(Settings(state_dir=state))
        first, second = Control(first_service), Control(second_service)
        try:
            await first.start()
            with pytest.raises(ValueError, match="already"):
                await second.start()
            assert (state / "control.sock").is_socket()
        finally:
            await second.close()
            await first.close()
            first_service.store.close()
            second_service.store.close()

    asyncio.run(check())
    assert not (state / "control.sock").exists()
