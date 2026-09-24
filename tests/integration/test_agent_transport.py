# SPDX-License-Identifier: Apache-2.0
"""Exercise an installed helper, native terminal and private inbox over real SSH."""

import json
import secrets
import shutil
import time

import pytest
from test_ssh import ssh_fixture as ssh_fixture
from test_terminal_transport import until

from ficc.ssh import PROBE
from ficc.terminal_pty import TerminalPTY


async def test_real_agent_inbox_reply_terminal_stop_and_archive(ssh_fixture):
    if not shutil.which("tmux"):
        pytest.fail("Tmux is required for the agent transport check.")
    transport, home, _ = ssh_fixture
    node = await transport.preview("fixture-node", "Agent fixture")
    await transport.install(node)
    controller, identity, terminal, run = [secrets.token_hex(16) for _ in range(4)]
    code = """import json,os,subprocess,time
helper=[os.environ['FICC_AGENT_PYTHON'],os.environ['FICC_AGENT_HELPER'],'--agent-tool']
print('FICC_AGENT_READY',flush=True)
for _ in range(200):
 result=subprocess.run(helper+['list'],capture_output=True,check=True)
 messages=json.loads(result.stdout)['messages']
 if messages:
  item=messages[0]
  subprocess.run(helper+['read',item['id']],capture_output=True,check=True)
  subprocess.run(helper+['send','--recipient',os.environ['FICC_AGENT_ID'],'--reply-to',item['message_id'],'--idempotency-key','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'],input=b'{"text":"Fixture reply"}',capture_output=True,check=True)
  print('FICC_REPLY_STORED',flush=True)
  break
 time.sleep(.05)
input()
"""
    profile = {"adapter": "generic", "argv": ["/usr/bin/python3", "-c", code], "workspace": str(home)}
    async def request(action, **extra):
        body = {"version": "3", "action": "agent." + action, "controller_id": controller, "agent_id": identity, **extra}
        status, output, _ = await transport.command(node, PROBE, json.dumps(body).encode() + b"\n")
        assert status == 0, output
        return json.loads(output)["result"]
    spec = {"controller_id": controller, "agent_id": identity, "terminal_controller": controller,
            "terminal_id": terminal, "run_id": run, "profile": profile, "version": "unversioned",
            "delivery_method": "inbox", "cols": 90, "rows": 30}
    pty = None
    try:
        await request("launch", spec=spec)
        args = await transport.arguments(node, terminal=True)
        args.append('exec python3 "$HOME/.local/lib/ficc/node.pyz" --attach-terminal ' + controller + " " + terminal)
        pty = TerminalPTY(args, 90, 30)
        await until(pty, b"FICC_AGENT_READY")
        delivery = {"id": "a" * 32, "agent_id": identity, "run_id": run, "message_id": "d" * 32,
                    "sender_id": "fixture-host", "type": "note", "body": {"text": "Structured inbox message"},
                    "method": "inbox", "authorization_expires_at": time.time() + 30}
        await request("exchange", deliveries=[delivery], receipt_ids=[], outbox_acks=[])
        await until(pty, b"FICC_REPLY_STORED")
        result = await request("exchange", deliveries=[delivery], receipt_ids=[delivery["id"]], outbox_acks=[])
        assert result["receipts"][0]["state"] == "tool-read"
        assert result["outbox"][0]["body"] == {"text": "Fixture reply"}
        assert result["outbox"][0]["recipient_ids"] == [identity]
        await request("exchange", deliveries=[], receipt_ids=[], outbox_acks=["b" * 32])
        assert (await request("stop"))["state"] == "stopped"
        archive = await request("archive")
        assert archive["state"] == "archived"
        assert await request("archive") == archive
        assert not (home / ".local/state/ficc/agents" / controller / identity).exists()
        assert (home / ".local/state/ficc/agents" / controller / ".archives" / identity / "spec.json").is_file()
    finally:
        if pty:
            await pty.close()
        # The exact session stop remains harmless after its agent spool was archived.
        body = {"version": "3", "action": "terminal.stop", "controller_id": controller, "terminal_id": terminal}
        await transport.command(node, PROBE, json.dumps(body).encode() + b"\n")
        await transport.close()
