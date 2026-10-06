# SPDX-License-Identifier: Apache-2.0
"""Run native Linux/macOS agent contracts with private, credential-free homes.

The baseline uses deterministic commands; FICC_TEST_OMP selects the pinned
OMP 18.1.12 executable for its real extension/RPC loop with a local scripted
stream, not a provider. No installed runtime configuration is inherited.
"""

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from ficc.ssh import archive

BASELINE = '''import json,os,subprocess,sys,time
if '--version' in sys.argv:
 print('unsupported fixture version'); sys.exit(0)
helper=[os.environ['FICC_AGENT_PYTHON'],os.environ['FICC_AGENT_HELPER'],'--agent-tool']
def tool(*args,body=None):
 p=subprocess.run(helper+list(args),input=json.dumps(body) if body else None,
                  capture_output=True,text=True,check=True,timeout=5)
 return json.loads(p.stdout)
print('FICC_BASELINE_READY',flush=True)
while True:
 for item in tool('list')['messages']:
  if item['body']['text']!='request':continue
  assert tool('read',item['id'])==item
  args=('send','--recipient',os.environ['FICC_AGENT_ID'],'--reply-to',item['message_id'],
        '--idempotency-key','b'*32)
  assert tool(*args,body={'text':'reply'})==tool(*args,body={'text':'reply'})
  print('FICC_BASELINE_REPLY',flush=True)
  while True:time.sleep(1)
 time.sleep(.1)
'''

# This extension supplies only deterministic model output. FICC's production
# extension remains responsible for native tool execution and message receipts.
OMP_PROVIDER = r'''
import { writeFileSync } from "node:fs";
export default function (pi: any) {
  let step = 0;
  pi.registerProvider("ficc-fixture", {
    baseUrl: "http://127.0.0.1:1", apiKey: "unused-fixture-value", api: "ficc-fixture",
    models: [{ id: "fixture", name: "Local scripted fixture", reasoning: false,
      input: ["text"], cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0},
      contextWindow: 32000, maxTokens: 1024 }],
    streamSimple(model: any) {
      const plan = [
        {action: "list"},
        {action: "read", delivery_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {action: "send", recipient_ids: [process.env.FICC_AGENT_ID],
         body: '{"text":"native OMP reply"}', reply_to: "dddddddddddddddddddddddddddddddd",
         idempotency_key: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        {action: "send", recipient_ids: [process.env.FICC_AGENT_ID],
         body: '{"text":"native OMP reply"}', reply_to: "dddddddddddddddddddddddddddddddd",
         idempotency_key: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        {action: "rejects"}
      ];
      const args = plan[step++];
      const reason = args ? "toolUse" : "stop";
      const message = {role: "assistant", api: model.api, provider: model.provider,
        model: model.id, timestamp: Date.now(), stopReason: reason,
        usage: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
          cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0}},
        content: args ? [{type: "toolCall", id: "fixture-"+step, name: "ficc_bus", arguments: args}]
                      : [{type: "text", text: "FICC_OMP_COMPLETE"}]};
      return {async *[Symbol.asyncIterator]() {
        yield {type: "start", partial: {...message, content: []}};
        if (args) {
          yield {type: "toolcall_start", contentIndex: 0, partial: structuredClone(message)};
          yield {type: "toolcall_delta", contentIndex: 0, delta: JSON.stringify(args),
                 partial: structuredClone(message)};
          yield {type: "toolcall_end", contentIndex: 0, toolCall: message.content[0],
                 partial: structuredClone(message)};
        } else {
          yield {type: "text_start", contentIndex: 0, partial: structuredClone(message)};
          yield {type: "text_delta", contentIndex: 0, delta: "FICC_OMP_COMPLETE",
                 partial: structuredClone(message)};
          yield {type: "text_end", contentIndex: 0, content: "FICC_OMP_COMPLETE",
                 partial: structuredClone(message)};
        }
        yield {type: "done", reason, message};
      }, result: async () => message};
    }
  });
  pi.on("tool_result", async (event: any) => {
    if (event.toolName === "ficc_bus") {
      if (event.isError) throw new Error("FICC bus tool failed");
      writeFileSync("tool-result-"+step+".json", JSON.stringify(event));
    }
  });
  pi.on("message_end", async (event: any) => {
    if (event.message?.customType === "ficc-bus")
      writeFileSync("included-"+event.message.details.deliveryId+".json", JSON.stringify(event.message));
  });
}
'''


class Node:
    def __init__(self, home):
        self.home = home
        self.helper = home / "node.pyz"
        self.helper.write_bytes(archive())
        self.controller, self.agent, self.terminal, self.run = [secrets.token_hex(16) for _ in range(4)]
        self.env = {"HOME": str(home), "PATH": os.environ["PATH"], "TERM": "xterm-256color",
                    "TMPDIR": "/tmp", "XDG_CONFIG_HOME": str(home / "config"),
                    "XDG_DATA_HOME": str(home / "data"), "XDG_CACHE_HOME": str(home / "cache"),
                    "FICC_CONTROLLER_ID": self.controller, "FICC_AGENT_ID": self.agent,
                    "NO_COLOR": "1", "HTTP_PROXY": "http://127.0.0.1:1",
                    "HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1"}
        self.folder = home / ".local/state/ficc/agents" / self.controller / self.agent
        # Retain exited panes for failure diagnostics; the fixture owns and
        # always kills this otherwise empty tmux server.
        self.tmux("start-server", ";", "set-option", "-s", "exit-empty", "off", ";",
                  "set-option", "-g", "remain-on-exit", "on")

    def command(self, argv, body=None, check=True):
        result = subprocess.run(argv, input=json.dumps(body) + "\n" if body is not None else None,
                                env=self.env, cwd=self.home, capture_output=True, text=True,
                                timeout=20, check=False)
        if check:
            assert result.returncode == 0, result.stdout + result.stderr
        return result

    def request(self, action, **extra):
        payload = {"version": "3", "action": "agent." + action, "controller_id": self.controller,
                   "agent_id": self.agent, **extra}
        if action == "probe":
            payload = {"version": "3", "action": "agent.probe", **extra}
        result = self.command([sys.executable, str(self.helper)], payload)
        return json.loads(result.stdout)["result"]

    def launch(self, adapter, argv):
        profile = {"adapter": adapter, "argv": argv, "workspace": str(self.home)}
        checked = self.request("probe", profile=profile)
        spec = {"controller_id": self.controller, "agent_id": self.agent,
                "terminal_controller": self.controller, "terminal_id": self.terminal,
                "run_id": self.run, "profile": profile, "version": checked["version"],
                "delivery_method": checked["delivery_method"], "cols": 100, "rows": 30}
        self.request("launch", spec=spec)
        self.until(lambda: self.request("status")["state"] == "ready")
        return checked

    def tmux(self, *args, check=True):
        return self.command(["tmux", "-f", "/dev/null", "-L", "ficc-" + self.controller, *args], check=check)

    def capture(self):
        return self.tmux("capture-pane", "-p", "-t", self.terminal, "-S", "-1000", check=False).stdout

    def until(self, condition, seconds=25):
        deadline = time.monotonic() + seconds
        while not condition():
            assert time.monotonic() < deadline, self.capture()
            time.sleep(.1)

    def deliver(self, method="inbox", identity="a" * 32):
        item = {"id": identity, "agent_id": self.agent, "run_id": self.run,
                "message_id": "d" * 32, "sender_id": "fixture-host", "type": "note",
                "body": {"text": "request"}, "method": method,
                "authorization_expires_at": time.time() + 60}
        self.request("exchange", deliveries=[item])
        return item

    def exchange(self, identities=None, acks=None):
        return self.request("exchange", receipt_ids=identities or ["a" * 32], outbox_acks=acks or [])


@pytest.fixture
def node():
    if not shutil.which("tmux"):
        pytest.fail("Install tmux for native agent contract tests.")
    # Keep Unix endpoint names short on both systems, including Darwin's sun_path.
    with tempfile.TemporaryDirectory(prefix="ficc-agent-", dir="/tmp") as folder:
        value = Node(Path(folder).resolve())
        try:
            yield value
        finally:
            value.tmux("kill-server", check=False)


@pytest.mark.parametrize("adapter", ["generic", "omp", "codex"])
def test_agent_profile_baseline_launch_inbox_reply_stop_archive(node, adapter):
    fixture = node.home / "fixture.py"
    fixture.write_text(BASELINE)
    checked = node.launch(adapter, [sys.executable, str(fixture)])
    assert checked["delivery_method"] == "inbox"
    node.until(lambda: "FICC_BASELINE_READY" in node.capture())
    node.deliver()
    node.until(lambda: len(node.exchange()["outbox"]) == 1)
    result = node.exchange()
    assert result["receipts"][0]["state"] == "tool-read"
    assert result["outbox"][0]["body"] == {"text": "reply"}
    assert result["outbox"][0]["recipient_ids"] == [node.agent]
    assert result["outbox"][0]["reply_to"] == "d" * 32
    assert node.exchange(acks=["b" * 32])["outbox"] == []
    assert node.request("stop")["state"] == "stopped"
    result = node.request("archive")
    assert result["state"] == "archived" and node.request("archive") == result
    assert not node.folder.exists()


def test_native_omp_direct_tool_reply_and_explicit_session_rebind(node):
    binary = os.environ.get("FICC_TEST_OMP")
    if not binary:
        if os.environ.get("FICC_REQUIRE_AGENT_RUNTIMES") == "1":
            pytest.fail("FICC_TEST_OMP must select OMP 18.1.12 for this native check.")
        pytest.skip("Set FICC_TEST_OMP to the pinned OMP 18.1.12 executable.")
    provider = node.home / "provider.ts"
    provider.write_text(OMP_PROVIDER)
    checked = node.launch("omp", [binary, "--mode", "rpc", "--no-extensions", "--no-skills",
        "--no-rules", "--no-lsp", "--no-title", "--no-tools", "--model", "ficc-fixture/fixture",
        "--extension", str(provider), "--allow-home"])
    assert checked["delivery_method"] == "direct" and "18.1.12" in checked["version"], checked
    original = node.request("status")["runtime_session_id"]
    node.deliver("direct")
    node.until(lambda: (node.home / "tool-result-5.json").exists())
    result = node.exchange()
    assert result["receipts"][0]["state"] == "tool-read"
    included = json.loads((node.home / ("included-" + "a" * 32 + ".json")).read_text())
    assert included["details"]["sessionId"] == original
    assert '"text":"request"' in included["content"]
    assert len(result["outbox"]) == 1
    assert result["outbox"][0]["body"] == {"text": "native OMP reply"}
    assert node.exchange(acks=["b" * 32])["outbox"] == []
    for step in range(1, 6):
        event = json.loads((node.home / f"tool-result-{step}.json").read_text())
        assert not event.get("isError")
    node.tmux("send-keys", "-t", node.terminal, "-l", '{"id":"switch","type":"new_session"}')
    node.tmux("send-keys", "-t", node.terminal, "Enter")
    node.until(lambda: node.request("status")["state"] == "suspended")
    changed = node.request("status")["observed_session_id"]
    assert changed != original
    node.deliver("direct", "c" * 32)
    assert node.exchange(["c" * 32])["receipts"][0]["state"] == "node-stored"
    node.request("rebind", runtime_session_id=changed)
    node.until(lambda: node.exchange(["c" * 32])["receipts"][0]["state"] == "session-included")
    assert node.request("stop")["state"] == "stopped"
    assert node.request("archive")["state"] == "archived"


def test_native_codex_thread_binding_stop_and_archive_without_model_turn(node):
    from ficc_node.agent_rpc import RPC

    binary = os.environ.get("FICC_TEST_CODEX")
    if not binary:
        if os.environ.get("FICC_REQUIRE_AGENT_RUNTIMES") == "1":
            pytest.fail("FICC_TEST_CODEX must select a supported Codex for this native check.")
        pytest.skip("Set FICC_TEST_CODEX to a supported Codex executable.")
    config = node.home / ".codex"
    config.mkdir(mode=0o700)
    (config / "config.toml").write_text(
        "[features]\nplugins=false\napps=false\nremote_plugin=false\n"
        "[analytics]\nenabled=false\n")
    checked = node.launch("codex", [binary, "-c", "check_for_update_on_startup=false"])
    assert checked["delivery_method"] == "direct", checked
    runtime = json.loads((node.folder / "runtime.json").read_text())
    endpoint = Path(runtime["rpc_endpoint"])
    rpc = RPC(endpoint)
    try:
        thread = rpc.call("thread/read", {"threadId": runtime["session_id"], "includeTurns": True})["thread"]
        assert thread["id"] == runtime["session_id"] and thread["turns"] == []
    finally:
        rpc.close()
    assert node.request("stop")["state"] == "stopped"
    node.until(lambda: not endpoint.exists())
    assert node.request("status")["state"] == "stopped"
    assert node.request("archive")["state"] == "archived"
