# SPDX-License-Identifier: Apache-2.0
"""Check private connection handling and the actual HTTP observation CLI workflow."""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from conftest import node, sample

from ficc import observation_cli
from ficc.api import create_app
from ficc.cli import main
from ficc.settings import Settings


def connection(tmp_path, controller="http://127.0.0.1:8170", token="a" * 43):
    token_path = tmp_path / "token"
    token_path.write_text(token + "\n")
    token_path.chmod(0o600)
    config = tmp_path / "connection.json"
    config.write_text(json.dumps({"controller": controller, "token_file": str(token_path)}))
    config.chmod(0o600)
    return config, token_path


@pytest.mark.parametrize("origin", [
    "http://example.com", "http://localhost:8170", "http://127.0.0.2", "http://2130706433",
    "https://user:PRIVATE@example.com", "https://example.com/?token=PRIVATE", "https://example.com/#fragment",
    "https://example.com/api", "https://example.com\\@127.0.0.1", "https://example.com\n",
    "https://example.com:0", "https://example.com:99999", "file:///tmp/token", "https://example%2ecom",
    "https://example.com?", "https://example.com#",
])
def test_connection_rejects_unsafe_origins(origin):
    with pytest.raises(ValueError):
        observation_cli.controller_origin(origin)


@pytest.mark.parametrize("origin", ["https://console.example.com", "https://console.example.com:8443/",
                                   "http://127.0.0.1:8170", "http://[::1]:8170"])
def test_connection_accepts_fixed_verified_origins(origin):
    assert observation_cli.controller_origin(origin) == origin.rstrip("/")


@pytest.mark.parametrize("fault", ["config-mode", "token-mode", "symlink", "parent-link", "directory", "fifo",
                                  "large", "token-large", "duplicate", "inline", "relative", "bad-token"])
def test_unsafe_private_files_fail_without_network_or_secret_output(tmp_path, monkeypatch, capsys, fault):
    config, token_path = connection(tmp_path, token="PRIVATE" + "a" * 36)
    if fault == "config-mode":
        config.chmod(0o644)
    elif fault == "token-mode":
        token_path.chmod(0o640)
    elif fault == "symlink":
        config.rename(tmp_path / "real.json")
        config.symlink_to(tmp_path / "real.json")
    elif fault == "parent-link":
        (tmp_path / "linked").symlink_to(tmp_path, target_is_directory=True)
        config = tmp_path / "linked" / config.name
    elif fault == "directory":
        token_path.unlink()
        token_path.mkdir()
    elif fault == "fifo":
        token_path.unlink()
        os.mkfifo(token_path, 0o600)
    elif fault == "large":
        config.write_bytes(b"x" * 4097)
    elif fault == "token-large":
        token_path.write_bytes(b"x" * 131)
    elif fault == "duplicate":
        config.write_text('{"controller":"https://private.example","controller":"https://public.example",'
                          '"token_file":"/tmp/token"}')
    elif fault == "inline":
        config.write_text(json.dumps({"controller": "https://example.com", "token": "PRIVATE"}))
    elif fault == "relative":
        config.write_text(json.dumps({"controller": "https://example.com", "token_file": "token"}))
    elif fault == "bad-token":
        token_path.write_text("PRIVATE\nHeader: bad")

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid private configuration reached the network.")

    monkeypatch.setattr(observation_cli.httpx, "Client", forbidden)
    assert main(["observe", "--connection", str(config), "nodes"]) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == observation_cli.ERROR + "\n"


@pytest.mark.parametrize("fault", ["redirect", "error", "length", "stream", "duplicate", "fields", "nan",
                                  "target", "compressed"])
def test_untrusted_responses_never_reflect_errors_or_excess_output(tmp_path, monkeypatch, capsys, fault):
    config, _ = connection(tmp_path)
    requests = []

    def streamed(raw):
        return httpx.Response(200, headers={"content-type": "application/json"},
                              stream=httpx.ByteStream(raw.encode()))

    def handler(request):
        requests.append(request)
        if fault == "redirect":
            return httpx.Response(302, headers={"Location": "https://attacker.example"}, text="PRIVATE")
        if fault == "error":
            return httpx.Response(403, text="PRIVATE")
        if fault == "length":
            return httpx.Response(200, headers={"content-type": "application/json", "content-length": "1048577"})
        if fault == "stream":
            return httpx.Response(200, headers={"content-type": "application/json"},
                                  stream=httpx.ByteStream(b"x" * (observation_cli.MAX_RESPONSE + 1)))
        if fault == "duplicate":
            return streamed('{"nodes":[],"nodes":[]}')
        if fault == "fields":
            return streamed(json.dumps({"nodes": [], "credential": "PRIVATE"}))
        if fault == "nan":
            return streamed('{"nodes":NaN}')
        if fault == "target":
            return streamed(json.dumps({"node_id": "node-1", "resources": None, "last_seen": None,
                                         "sample_age_seconds": None, "stale": True}))
        return httpx.Response(200, headers={"content-encoding": "deflate", "content-type": "application/json"},
                              stream=httpx.ByteStream(b"PRIVATE"))

    original = httpx.Client

    def client(**kwargs):
        assert kwargs["verify"] is True and kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        return original(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(observation_cli.httpx, "Client", client)
    command = ["resources", "--node", "node-0"] if fault == "target" else ["nodes"]
    assert main(["observe", "--connection", str(config), *command]) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == observation_cli.ERROR + "\n"
    assert len(requests) == 1 and requests[0].url.host == "127.0.0.1"


@pytest.mark.parametrize("identity", ["../node-0", "node-0?token=PRIVATE", "https://attacker.example", "a/b", "node%2f0"])
def test_node_identity_cannot_change_request_destination(tmp_path, monkeypatch, capsys, identity):
    config, _ = connection(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid machine identity reached the network.")

    monkeypatch.setattr(observation_cli.httpx, "Client", forbidden)
    assert main(["observe", "--connection", str(config), "resources", "--node", identity]) == 1
    assert capsys.readouterr().out == ""


def test_real_controller_and_subprocess_cli_use_only_narrow_token(tmp_path, monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    app = create_app(Settings(state_dir=tmp_path / "state", port=port, control=False, demo=True,
                              poll_interval=3600, stale_after=7200))
    service = app.state.service
    value = node()
    value.update(resources=sample()["resources"], state="ready", last_seen=time.time())
    service.store.save_node(value)
    service.store.save_node(node(1))
    user = service.auth.identities.create("user", "CLI observer")
    project = service.auth.identities.create("project", "CLI project")
    scopes = ["observations:read", "observations:resources"]
    service.auth.identities.membership(project["id"], user["id"], scopes, 0)
    service.auth.resources.save(project["id"], ["node-0", "node-1"], [], 0)
    secret, actor = service.auth.issue("token", scopes=scopes, node_ids=["node-0"],
                                       subject_id=user["id"], project_id=project["id"])
    config, _ = connection(tmp_path, f"http://127.0.0.1:{port}", secret)
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    deadline = time.monotonic() + 10
    try:
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started

        def run(*args):
            result = subprocess.run([sys.executable, "-m", "ficc.cli", "observe", "--connection", str(config), *args],
                                    capture_output=True, text=True, timeout=20,
                                    cwd=Path(__file__).resolve().parents[2])
            assert secret not in result.stdout + result.stderr
            return result

        listed = run("nodes")
        assert listed.returncode == 0 and listed.stderr == ""
        assert [row["id"] for row in json.loads(listed.stdout)["nodes"]] == ["node-0"]
        result = run("resources", "--node", "node-0")
        assert result.returncode == 0 and result.stderr == ""
        assert json.loads(result.stdout)["resources"] == sample()["resources"]
        assert all(private not in listed.stdout + result.stdout
                   for private in ("synthetic-key", "operator", "machine-0.example", "lab-0"))
        denied = run("resources", "--node", "node-1")
        assert denied.returncode == 1 and denied.stdout == "" and denied.stderr == observation_cli.ERROR + "\n"
        service.auth.revoke(actor.id)
        denied = run("nodes")
        assert denied.returncode == 1 and denied.stdout == ""
        events = [event for event in service.store.events() if event["action"].startswith("observation.")]
        assert events and all(event["actor"] == actor.id and event["subject_id"] == user["id"]
                              and event["project_id"] == project["id"] for event in events)
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        listener.close()
        assert not thread.is_alive()
