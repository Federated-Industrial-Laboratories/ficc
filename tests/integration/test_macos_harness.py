# SPDX-License-Identifier: Apache-2.0
"""Opt-in real SSH qualification of a Mac node's agent harness.

Set FICC_MACOS_PROFILE to an already trusted SSH alias with this helper installed.
FICC_MACOS_SSH_CONFIG optionally selects its SSH configuration. All controller
state and remote fixture workspaces are isolated and cleaned after the test.
"""

import asyncio
import json
import os
import secrets
import shlex
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ficc.api import create_app
from ficc.settings import Settings

FIXTURE = '''import json,os,pathlib,subprocess,time
workspace=pathlib.Path.cwd()
assert subprocess.check_output(["/usr/bin/uname","-s"]).strip()==b"Darwin"
(workspace/"written.txt").write_text("native file tool works")
assert (workspace/"written.txt").read_text()=="native file tool works"
command=[os.environ["FICC_AGENT_PYTHON"],os.environ["FICC_AGENT_HELPER"],"--agent-tool"]
def tool(*args,body=None):
 result=subprocess.run(command+list(args),input=json.dumps(body) if body else None,
                       text=True,capture_output=True,check=True,timeout=10)
 return json.loads(result.stdout)
print("FICC_MACOS_HARNESS_READY",flush=True)
seen=set()
while True:
 for item in tool("list")["messages"]:
  if item["id"] in seen or item["body"]["text"]!="native harness request":continue
  seen.add(item["id"])
  assert tool("read",item["id"])["body"]["text"]=="native harness request"
  arguments=("send","--recipient",os.environ["FICC_AGENT_ID"],"--reply-to",item["message_id"],
             "--idempotency-key",item["id"])
  body={"text":"native harness response"}
  first=tool(*arguments,body=body)
  assert tool(*arguments,body=body)["id"]==first["id"]
  assert tool("rejects")["rejections"]==[]
  print("FICC_MACOS_HARNESS_REPLIED",flush=True)
 time.sleep(.2)
'''


def test_native_mac_agent_tools_and_bus(tmp_path):
    profile = os.environ.get("FICC_MACOS_PROFILE")
    if not profile:
        pytest.skip("Set FICC_MACOS_PROFILE for the native Mac harness test")
    config = os.environ.get("FICC_MACOS_SSH_CONFIG")
    prefix = ["ssh", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes"]
    if config:
        prefix += ["-F", config]

    def remote(script, payload=""):
        return subprocess.run(prefix + ["--", profile, "python3 -c " + shlex.quote(script)],
                              input=payload, capture_output=True, text=True, timeout=20, check=True).stdout

    workspace = remote("import pathlib,tempfile,sys; "
        "root=pathlib.Path.home()/'.local/share/ficc'; root.mkdir(parents=True,exist_ok=True); "
        "folder=pathlib.Path(tempfile.mkdtemp(prefix='harness-test-',dir=root)); "
        "(folder/'fixture.py').write_text(sys.stdin.read()); print(folder)", FIXTURE).strip()
    app = create_app(Settings(state_dir=tmp_path / "state", profiles=(profile,), control=False,
                              ssh_config=Path(config) if config else None))
    service = app.state.service
    agent = run = None
    try:
        with TestClient(app, base_url="http://127.0.0.1:8170") as client:
            credential, actor = service.auth.issue("bootstrap", lifetime=60)
            session = client.post("/api/v1/session", json={"bootstrap": credential},
                                  headers={"Origin": "http://127.0.0.1:8170"})
            session.raise_for_status()
            client.headers.update({"Origin": "http://127.0.0.1:8170",
                                   "X-CSRF-Token": session.json()["csrf"]})

            def post(path, body):
                result = client.post("/api/v1/" + path, json=body)
                assert result.status_code == 200, result.text
                return result.json()

            preview = post("node-previews", {"profile": profile, "name": "Native Mac fixture"})
            assert preview["trust"] == "trusted" and not preview["helper_install_required"]
            node = post("nodes", {"preview_id": preview["preview_id"],
                "expected_fingerprint": preview["fingerprint"], "install_helper": False})
            assert node["capabilities"]["source"] == "macos-mach-sysctl"
            registered = asyncio.run(service.agents.register({"node_id": node["id"],
                "name": "Native fixture", "adapter": "generic", "workspace": workspace,
                "argv": ["/usr/bin/python3", workspace + "/fixture.py"]}))
            try:
                run = post("bus/runs", {"name": "native-mac-harness", "idempotency_key": secrets.token_hex(16)})
                preview = post("agent-previews", {"profile_id": registered["id"], "label": "Native fixture",
                                                  "run_id": run["id"]})
                intent = {"preview_id": preview["preview_id"], "idempotency_key": secrets.token_hex(16),
                          "confirm_execution": True}
                agent = post("agents", intent)
                assert post("agents", intent)["id"] == agent["id"]
                message = post(f"bus/runs/{run['id']}/messages", {"type": "note",
                    "body": {"text": "native harness request"}, "recipient_ids": [agent["id"]],
                    "delivery": "inbox", "reply_to": None, "idempotency_key": secrets.token_hex(16),
                    "confirm_delivery": True})
                deadline = time.monotonic() + 30
                while True:
                    messages = client.get(f"/api/v1/bus/runs/{run['id']}/messages").json()["messages"]
                    replies = [item for item in messages if item["sender_id"] == agent["id"]]
                    if replies:
                        assert len(replies) == 1 and replies[0]["body"]["text"] == "native harness response"
                        assert replies[0]["reply_to"] == message["message"]["id"]
                        break
                    assert time.monotonic() < deadline, "The native agent did not complete its tool round trip"
                    time.sleep(.2)
                assert service.bus.deliveries()[0]["state"] == "tool-read"
                ticket = post(f"terminals/{agent['terminal_id']}/tickets", {})
                with client.websocket_connect("ws://127.0.0.1:8170" + ticket["websocket_path"],
                        headers={"Origin": "http://127.0.0.1:8170"}) as stream:
                    stream.send_json({"type": "auth", "ticket": ticket["ticket"]})
                    output = b""
                    while b"FICC_MACOS_HARNESS_REPLIED" not in output:
                        frame = stream.receive()
                        if frame.get("bytes"):
                            output += frame["bytes"]
                            stream.send_json({"type": "ack", "bytes": len(frame["bytes"])})
                        elif frame.get("text"):
                            assert json.loads(frame["text"]).get("state") == "attached", frame
                print("Native agent: file/process tools, inbox list/read, reply/dedup, receipts and PTY passed")
            finally:
                if agent:
                    assert post(f"agents/{agent['id']}/stop", {"confirm_stop": True})["state"] == "stopped"
                if run:
                    deadline = time.monotonic() + 10
                    while True:
                        closed = client.post(f"/api/v1/bus/runs/{run['id']}/close", json={"confirm_close": True})
                        if closed.status_code == 200:
                            break
                        assert time.monotonic() < deadline, closed.text
                        time.sleep(.2)
    finally:
        # Remove only namespaces generated by this isolated controller.
        remote("import json,pathlib,shutil,sys; value=json.loads(sys.stdin.read()); "
               "shutil.rmtree(value['workspace']); "
               "root=pathlib.Path.home()/'.local/state/ficc'; "
               "[shutil.rmtree(root/k/v,ignore_errors=True) for k,v in value['namespaces'].items()]",
               json.dumps({"workspace": workspace, "namespaces": {
                   "agents": service.agents.controller, "terminals": service.terminals.controller}}))
