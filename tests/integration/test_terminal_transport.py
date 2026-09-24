# SPDX-License-Identifier: Apache-2.0
"""Exercise PTY resize and persistent session lifecycle over isolated OpenSSH."""

import asyncio
import json
import shutil

import pytest
from test_ssh import ssh_fixture as ssh_fixture

from ficc.ssh import PROBE
from ficc.terminal_pty import TerminalPTY


async def until(pty, marker):
    output = bytearray()
    async with asyncio.timeout(10):
        while marker not in output:
            chunk = await pty.read()
            if not chunk:
                pytest.fail("The PTY closed before the expected marker.")
            output.extend(chunk)
            if len(output) > 262144:
                pytest.fail("The PTY response exceeded the fixture limit.")
    return bytes(output)


async def test_pinned_ssh_pty_resize_and_input(ssh_fixture):
    transport, _, _ = ssh_fixture
    node = await transport.preview("fixture-node", "PTY fixture")
    args = await transport.arguments(node, terminal=True)
    assert "RequestTTY=force" in args and "EscapeChar=none" in args
    pty = TerminalPTY(args + ["exec /bin/sh"], 93, 31)
    try:
        await pty.write(b"stty -echo; printf '\\120\\124\\131_READY\\n'\n")
        await until(pty, b"PTY_READY")
        pty.resize(101, 37)
        await pty.write(b"stty size; printf '\\104ONE_SIZE\\n'\n")
        result = await until(pty, b"DONE_SIZE")
        assert b"37 101" in result
        await pty.write(b"printf '\\000\\377\\102\\131\\124\\105\\123\\n'\n")
        result = await until(pty, b"BYTES")
        assert b"\x00\xffBYTES" in result
        await pty.write(b"exit\n")
    finally:
        await pty.close()


async def test_tmux_dedup_detach_reattach_and_exact_stop(ssh_fixture):
    if not shutil.which("tmux"):
        pytest.fail("Tmux is required for terminal integration checks.")
    transport, home, _ = ssh_fixture
    node = await transport.preview("fixture-node", "Tmux fixture")
    await transport.install(node)
    sample = await transport.probe(node)
    if not sample["capabilities"]["terminals_tmux"]:
        code, output, _ = await transport.command(node, 'printf "%s\\n" "$PATH"; command -v tmux', b"")
        pytest.fail("Tmux fixture PATH: " + output.decode())
    assert sample["helper_version"] == "3"
    controller, terminal, neighbor = "c" * 32, "d" * 32, "e" * 32

    async def request(action, identity=terminal):
        body = {"version": "3", "action": "terminal." + action, "controller_id": controller, "terminal_id": identity}
        if action == "create":
            body.update(cols=80, rows=24)
        code, output, _ = await transport.command(node, PROBE, json.dumps(body).encode() + b"\n")
        assert code == 0, output
        return json.loads(output)["result"]["state"]

    async def attach():
        args = await transport.arguments(node, terminal=True)
        args.append('exec python3 "$HOME/.local/lib/ficc/node.pyz" --attach-terminal ' + controller + " " + terminal)
        return TerminalPTY(args, 80, 24)

    try:
        assert await request("create") == "detached"
        assert await request("create") == "detached"
        assert await request("create", neighbor) == "detached"
        assert len(list((home / ".local/state/ficc/terminals" / controller).glob("*.json"))) == 2
        pty = await attach()
        try:
            await pty.write(b"stty -echo; export FICC_REATTACH_PROOF=retained; printf '\\122EADY_FIRST\\n'\n")
            await until(pty, b"READY_FIRST")
        finally:
            await pty.close()
        assert await request("status") == "detached"
        pty = await attach()
        try:
            await pty.write(b"printf '\\120ROOF_%s\\n' \"$FICC_REATTACH_PROOF\"\n")
            await until(pty, b"PROOF_retained")
        finally:
            await pty.close()
        assert await request("stop") == "stopped"
        assert await request("stop") == "stopped"
        assert await request("status", neighbor) == "detached"
        assert await request("create") == "stopped"
        pty = await attach()
        try:
            async with asyncio.timeout(10):
                output = bytearray()
                while chunk := await pty.read():
                    output.extend(chunk)
                assert b"no longer available" in output
        finally:
            await pty.close()
    finally:
        await request("stop")
        await request("stop", neighbor)
