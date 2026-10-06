# SPDX-License-Identifier: Apache-2.0
"""Opt-in real Codex 0.160.1 qualification on a trusted native Mac.

This test calls the configured model provider. Enable it explicitly with
FICC_MACOS_REAL_CODEX=1 and FICC_MACOS_PROFILE. Credentials and the model
selection stay in the installed runtime configuration.
"""

import asyncio
import json
import os
import re
import secrets
import shlex
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ficc.api import create_app
from ficc.settings import Settings


def test_real_codex_native_tools_and_direct_bus(tmp_path):
    root = tmp_path
    profile_name = os.environ.get("FICC_MACOS_PROFILE")
    if not profile_name or os.environ.get("FICC_MACOS_REAL_CODEX") != "1":
        pytest.skip("Set FICC_MACOS_PROFILE and FICC_MACOS_REAL_CODEX=1 to allow real model calls")
    config = os.environ.get("FICC_MACOS_SSH_CONFIG")
    prefix = ["ssh", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes"]
    if config:
        prefix += ["-F", config]
    prefix += ["--", profile_name]

    def remote(script, payload="", timeout=20):
        result = subprocess.run(
            prefix + ["python3 -c " + shlex.quote(script)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(result.stderr[:4000])
        return result.stdout

    def capture_terminal():
        return remote(
            "import subprocess,json,sys; c,a=json.loads(sys.stdin.read()); "
            "r=subprocess.run(['/opt/homebrew/bin/tmux','-L','ficc-'+c,'capture-pane',"
            "'-p','-t',a+':0.0','-S','-150'],capture_output=True,text=True,timeout=5); "
            "print(r.stdout or r.stderr)",
            json.dumps([service.terminals.controller, agent["terminal_id"]]),
        )

    def record_tools():
        return json.loads(remote(
            """import pathlib,json,sys,time
v=json.loads(sys.stdin.read())
sys.path.insert(0,str(pathlib.Path.home()/'.local/lib/ficc/node.pyz'))
from ficc_node.agent_rpc import RPC
folder=pathlib.Path(v['folder'])
markers=pathlib.Path(v['workspace'])
r=json.loads((folder/'runtime.json').read_text())
rpc=RPC(r['rpc_endpoint'])
rows=[]
try:
 rpc.call('thread/resume',{'threadId':r['session_id'],'excludeTurns':True})
 (markers/'evidence-ready').touch(mode=0o600)
 deadline=time.monotonic()+250
 while time.monotonic()<deadline:
  rpc.call('thread/read',{'threadId':r['session_id'],'includeTurns':False})
  for event in rpc.events:
   params=event.get('params',{})
   item=params.get('item',{})
   if (event.get('method')=='item/completed' and params.get('threadId')==r['session_id']
       and item.get('type')=='commandExecution'):
    rows.append(item)
  rpc.events.clear()
  if (markers/'evidence-stop').exists(): break
  time.sleep(.2)
 print(json.dumps(rows))
finally: rpc.close()
""", json.dumps({"folder": spool + "/" + agent["id"], "workspace": workspace}), timeout=270))

    info = json.loads(
        remote(
            "import json,pathlib,tempfile; h=pathlib.Path.home(); "
            "(h/'.local/share/ficc').mkdir(parents=True,exist_ok=True); "
            "w=tempfile.mkdtemp(prefix='codex-harness-',dir=h/'.local/share/ficc'); "
            "print(json.dumps({'home':str(h),'workspace':w}))"
        )
    )
    workspace = info["workspace"]
    app = create_app(
        Settings(
            state_dir=root / "state",
            profiles=(profile_name,),
            control=False,
            ssh_config=Path(config) if config else None,
        )
    )
    service = app.state.service
    marker = "ficc-codex-request-" + secrets.token_hex(6)
    reply = "FICC_CODEX_NATIVE_OK_" + secrets.token_hex(6)
    key = secrets.token_hex(16)
    prompt = (
        "Run this operator-requested FICC integration smoke test only. Use your shell tools to run uname -s "
        "and verify Darwin, write written.txt containing exactly native file tool works, and read it back with cat written.txt. "
        "Use the inherited FICC environment with correct quoting: "
        '"$FICC_AGENT_PYTHON" "$FICC_AGENT_HELPER" --agent-tool list. '
        "Poll that command once per second for at most 45 seconds until body.text contains "
        + marker
        + ". "
        "Read that exact item with the same command and --agent-tool read DELIVERY_ID. "
        "Then pipe JSON "
        + json.dumps({"text": reply})
        + " to the same command with --agent-tool send "
        '--recipient "$FICC_AGENT_ID" --delivery inbox --reply-to MESSAGE_ID --idempotency-key '
        + key
        + ". "
        "Use the delivery ID and message ID from the inbox. This one reply to yourself is explicitly "
        "authorized for the test. Retry the same send with identical content and idempotency key and "
        "verify it returns the same ID. Use separate shell calls for each operation and both sends. Then use --agent-tool rejects and verify no rejections. "
        "Do not read credentials, alter configuration, contact other recipients, or perform unrelated work. "
        "In your final response state the kernel, file readback, read delivery ID and send ID. Exit after completion."
    )
    assert len(prompt) < 2048
    evidence_future = None
    evidence_pool = ThreadPoolExecutor(max_workers=1)
    agent = run = None
    stop_confirmed = True
    print("Private qualification artifacts:", root, flush=True)
    try:
        with TestClient(app, base_url="http://127.0.0.1:8170") as client:
            credential, _ = service.auth.issue("bootstrap", lifetime=600)
            session = client.post(
                "/api/v1/session",
                json={"bootstrap": credential},
                headers={"Origin": "http://127.0.0.1:8170"},
            )
            session.raise_for_status()
            client.headers.update(
                {"Origin": "http://127.0.0.1:8170", "X-CSRF-Token": session.json()["csrf"]}
            )

            def post(path, body):
                response = client.post("/api/v1/" + path, json=body)
                assert response.status_code == 200, (response.status_code, response.text)
                return response.json()

            preview = post(
                "node-previews", {"profile": profile_name, "name": "Native Codex qualification"}
            )
            assert preview["trust"] == "trusted" and not preview["helper_install_required"]
            node = post(
                "nodes",
                {
                    "preview_id": preview["preview_id"],
                    "expected_fingerprint": preview["fingerprint"],
                    "install_helper": False,
                },
            )
            spool = info["home"] + "/.local/state/ficc/agents/" + service.agents.controller
            argv = [os.environ.get("FICC_MACOS_CODEX", info["home"] + "/.local/bin/codex")]
            profile = asyncio.run(
                service.agents.register(
                    {
                        "node_id": node["id"],
                        "name": "Real Codex qualification",
                        "adapter": "codex",
                        "workspace": workspace,
                        "argv": argv,
                    }
                )
            )
            assert (
                profile["version"] == "codex-cli 0.160.1" and profile["delivery_method"] == "direct"
            ), profile
            print(
                "Registered actual runtime:",
                profile["version"],
                profile["delivery_method"],
                flush=True,
            )
            try:
                run = post(
                    "bus/runs",
                    {
                        "name": "native-codex-qualification",
                        "idempotency_key": secrets.token_hex(16),
                    },
                )
                preview = post(
                    "agent-previews",
                    {
                        "profile_id": profile["id"],
                        "label": "Real Codex qualification",
                        "run_id": run["id"],
                    },
                )
                remote(
                    "import subprocess,sys; c=sys.stdin.read(); "
                    "b=['/opt/homebrew/bin/tmux','-f','/dev/null','-L','ficc-'+c]; "
                    "subprocess.run(b+['new-session','-d','-s','capture-keeper','sleep','360'],check=True); "
                    "subprocess.run(b+['set-window-option','-g','remain-on-exit','on'],check=True)",
                    service.terminals.controller,
                )
                stop_confirmed = False
                agent = post(
                    "agents",
                    {
                        "preview_id": preview["preview_id"],
                        "idempotency_key": secrets.token_hex(16),
                        "confirm_execution": True,
                    },
                )
                print("Codex launched through FICC:", agent["state"], flush=True)
                # Configure only this disposable thread's writable roots, preserving its approval policy.
                time.sleep(3)
                idle = client.get("/api/v1/agents/" + agent["id"]).json()
                assert idle["state"] == "ready", idle
                remote(
                    "import pathlib,json,sys; v=json.loads(sys.stdin.read()); "
                    "sys.path.insert(0,str(pathlib.Path.home()/'.local/lib/ficc/node.pyz')); "
                    "from ficc_node.agent_rpc import RPC; "
                    "r=json.loads((pathlib.Path(v['spool'])/v['agent']/'runtime.json').read_text()); "
                    "rpc=RPC(r['rpc_endpoint']); "
                    "rpc.call('thread/settings/update',{'threadId':r['session_id'],'sandboxPolicy':"
                    "{'type':'workspaceWrite','writableRoots':[v['workspace'],v['spool']],"
                    "'networkAccess':False,'excludeTmpdirEnvVar':False,'excludeSlashTmp':False}}); rpc.close()",
                    json.dumps({"spool": spool, "agent": agent["id"], "workspace": workspace}),
                )
                evidence_future = evidence_pool.submit(record_tools)
                deadline = time.monotonic() + 15
                while remote(
                    "import pathlib,sys; print((pathlib.Path(sys.stdin.read())/'evidence-ready').exists())",
                    workspace,
                ).strip() != "True":
                    if evidence_future.done():
                        evidence_future.result()
                        raise AssertionError("Tool recorder exited before subscribing")
                    assert time.monotonic() < deadline, "Tool recorder did not subscribe"
                    time.sleep(.1)
                message = post(
                    "bus/runs/" + run["id"] + "/messages",
                    {
                        "type": "note",
                        "body": {"text": marker},
                        "recipient_ids": [agent["id"]],
                        "delivery": "direct",
                        "reply_to": None,
                        "idempotency_key": secrets.token_hex(16),
                        "confirm_delivery": True,
                    },
                )
                remote(
                    "import json,subprocess,sys,time; v=json.loads(sys.stdin.read()); "
                    "b=['/opt/homebrew/bin/tmux','-L','ficc-'+v['controller'],'send-keys','-t',v['terminal']+':0.0']; "
                    "subprocess.run(b+['-l',v['prompt']],check=True); time.sleep(.5); "
                    "subprocess.run(b+['Enter'],check=True)",
                    json.dumps(
                        {
                            "controller": service.terminals.controller,
                            "terminal": agent["terminal_id"],
                            "prompt": prompt
                            + " Also write your final result to final.txt in the workspace.",
                        }
                    ),
                )
                delivery = message["deliveries"][0]["id"]
                deadline = time.monotonic() + 240
                next_report = time.monotonic() + 1
                while True:
                    messages = client.get("/api/v1/bus/runs/" + run["id"] + "/messages").json()[
                        "messages"
                    ]
                    replies = [item for item in messages if item["sender_id"] == agent["id"]]
                    receipt = next(
                        item for item in service.bus.deliveries() if item["id"] == delivery
                    )
                    status = client.get("/api/v1/agents/" + agent["id"]).json()
                    files = json.loads(
                        remote(
                            "import json,pathlib,sys; w=pathlib.Path(sys.stdin.read()); "
                            "print(json.dumps({n:(w/n).read_text() if (w/n).exists() else None "
                            "for n in ('written.txt','final.txt')}))",
                            workspace,
                        )
                    )
                    (root / "observations.json").write_text(json.dumps(files))
                    if replies and files["final.txt"] and receipt["state"] == "session-included":
                        assert len(replies) == 1 and replies[0]["body"]["text"] == reply, replies
                        assert replies[0]["reply_to"] == message["message"]["id"]
                        assert receipt["state"] == "session-included", receipt
                        assert status["state"] == "ready", status
                        assert files["written.txt"] == "native file tool works", files
                        assert "Darwin" in files["final.txt"] and key in files["final.txt"], files
                        remote(
                            "import pathlib,sys; (pathlib.Path(sys.stdin.read())/'evidence-stop').touch(mode=0o600)",
                            workspace,
                        )
                        evidence = evidence_future.result(timeout=15)
                        (root / "tool-evidence.json").write_text(json.dumps(evidence))
                        completed = [item for item in evidence if item.get("exitCode") == 0]
                        assert any(
                            "uname -s" in item["command"]
                            and item.get("aggregatedOutput", "").strip() == "Darwin"
                            for item in completed
                        )
                        assert any(
                            "cat written.txt" in item["command"]
                            and "native file tool works" in item.get("aggregatedOutput", "")
                            for item in completed
                        )

                        def results(action):
                            values = []
                            for item in completed:
                                if not re.search(
                                    r"--agent-tool['\"]?\s+['\"]?" + action + r"\b", item["command"]
                                ):
                                    continue
                                for line in item.get("aggregatedOutput", "").splitlines():
                                    try:
                                        values.append(json.loads(line))
                                    except ValueError:
                                        continue
                            return values

                        assert any(
                            any(row["id"] == delivery for row in value.get("messages", []))
                            for value in results("list")
                        )
                        assert any(
                            value.get("id") == delivery
                            and value.get("message_id") == message["message"]["id"]
                            for value in results("read")
                        )
                        sends = [
                            value
                            for value in results("send")
                            if value.get("id") == key
                            and value.get("state") in {"node-stored", "host-stored"}
                        ]
                        assert len(sends) >= 2, sends
                        assert any(value.get("rejections") == [] for value in results("rejects"))
                        print(
                            "PASS: actual Codex model used shell/file tools, read inbox and replied through FICC.",
                            flush=True,
                        )
                        print(
                            "Verified direct inclusion, real model tools, reply deduplication and runtime readiness.",
                            flush=True,
                        )
                        (root / "result.json").write_text(
                            json.dumps(
                                {
                                    "runtime": profile["version"],
                                    "delivery": receipt["state"],
                                    "reply": "host-stored",
                                    "messages": len(replies),
                                    "final": files["final.txt"],
                                    "file": files["written.txt"],
                                }
                            )
                        )
                        break
                    if time.monotonic() >= next_report or status.get("state") == "exited":
                        print(
                            "Waiting for Codex:",
                            status.get("state"),
                            "receipt:",
                            receipt["state"],
                            flush=True,
                        )
                        (root / "terminal.txt").write_text(capture_terminal())
                        next_report = time.monotonic() + 5
                    assert time.monotonic() < deadline, (
                        "Real Codex round trip did not complete; inspect private terminal capture"
                    )
                    assert status.get("state") not in {"stopped", "exited", "failed"}, status
                    time.sleep(1)
            finally:
                cleanup_errors = []
                if evidence_future and not evidence_future.done():
                    try:
                        remote(
                            "import pathlib,sys; (pathlib.Path(sys.stdin.read())/'evidence-stop').touch(mode=0o600)",
                            workspace,
                        )
                        evidence_future.result(timeout=15)
                    except Exception as error:
                        cleanup_errors.append(str(error))
                if agent:
                    try:
                        (root / "terminal.txt").write_text(capture_terminal())
                    except Exception as error:
                        print("Diagnostic capture unavailable:", error, flush=True)
                    try:
                        stopped = post("agents/" + agent["id"] + "/stop", {"confirm_stop": True})
                        assert stopped["state"] == "stopped", stopped
                        stop_confirmed = True
                        print("Stopped real Codex qualification agent.", flush=True)
                    except Exception as error:
                        cleanup_errors.append(str(error))
                if run:
                    try:
                        deadline = time.monotonic() + 15
                        while True:
                            closed = client.post(
                                "/api/v1/bus/runs/" + run["id"] + "/close",
                                json={"confirm_close": True},
                            )
                            if closed.status_code == 200:
                                print("Closed qualification run.", flush=True)
                                break
                            assert time.monotonic() < deadline, closed.text
                            time.sleep(0.2)
                    except Exception as error:
                        cleanup_errors.append(str(error))
                if cleanup_errors:
                    raise RuntimeError("Qualification cleanup failed: " + "; ".join(cleanup_errors))
    finally:
        evidence_pool.shutdown(wait=True)
        try:
            remote(
                "import subprocess,sys; subprocess.run(['/opt/homebrew/bin/tmux','-L','ficc-'+sys.stdin.read(),'kill-server'],check=False,timeout=5)",
                service.terminals.controller,
            )
        except Exception as error:
            print("Test tmux cleanup unavailable:", error, flush=True)
        if stop_confirmed:
            remote(
                "import json,pathlib,shutil,sys; v=json.loads(sys.stdin.read()); "
                "shutil.rmtree(v['workspace']); root=pathlib.Path.home()/'.local/state/ficc'; "
                "[shutil.rmtree(root/k/v,ignore_errors=True) for k,v in v['namespaces'].items()]",
                json.dumps(
                    {
                        "workspace": workspace,
                        "namespaces": {
                            "agents": service.agents.controller,
                            "terminals": service.terminals.controller,
                        },
                    }
                ),
            )
        else:
            print(
                "Termination unconfirmed; retained remote workspace and namespaces:",
                workspace,
                service.agents.controller,
                service.terminals.controller,
                flush=True,
            )
