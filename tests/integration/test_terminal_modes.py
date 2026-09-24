# SPDX-License-Identifier: Apache-2.0
"""Verify normal SSH terminal discipline and explicit raw-program transport."""

import asyncio
import json
import shlex

import pytest
from test_ssh import ssh_fixture as ssh_fixture
from test_terminal_transport import until

from ficc.terminal_pty import TerminalPTY


async def start(transport, command):
    node = await transport.preview("fixture-node", "Terminal mode fixture")
    args = await transport.arguments(node, terminal=True)
    return TerminalPTY(args + [command], 93, 31)


def python_command(source):
    return "exec python3 -u -c " + shlex.quote(source)


async def test_remote_normal_stty_flags_and_crlf_output(ssh_fixture):
    transport, _, _ = ssh_fixture
    pty = await start(transport, "stty -a; printf 'LINE_ONE\\nLINE_TWO\\nMODES_DONE\\n'")
    try:
        output = await until(pty, b"MODES_DONE")
        words = output.decode().replace(";", " ").split()
        for flag in ("icanon", "icrnl", "opost", "onlcr", "isig", "echo"):
            assert flag in words and "-" + flag not in words, output
        assert b"LINE_ONE\r\nLINE_TWO\r\nMODES_DONE" in output
    finally:
        await pty.close()


@pytest.mark.parametrize("count", [1, 64])
async def test_enter_completes_each_remote_line_read(ssh_fixture, count):
    transport, _, _ = ssh_fixture
    program = ("import sys,json,signal;signal.alarm(15);print('LINE_READY',flush=True)\n"
               f"for index in range({count}):\n"
               " data=sys.stdin.buffer.readline()\n"
               " print('RESULT_'+str(index)+'='+json.dumps(data.hex()),flush=True)\n")
    pty = await start(transport, python_command(program))
    try:
        await until(pty, b"LINE_READY")
        for index in range(count):
            data = f"line-{index}-caf\N{LATIN SMALL LETTER E WITH ACUTE}".encode()
            await pty.write(data + b"\r")
            output = await until(pty, b"RESULT_" + str(index).encode() + b"=")
            while not output.endswith(b"\n"):
                async with asyncio.timeout(5):
                    chunk = await pty.read()
                    assert chunk, "The remote line reader closed before its result."
                    output += chunk
            result = output.split(b"RESULT_" + str(index).encode() + b"=", 1)[1].splitlines()[0]
            assert bytes.fromhex(json.loads(result)) == data + b"\n", output
    finally:
        await pty.close()


async def test_ctrl_c_interrupts_foreground_program_and_keeps_shell(ssh_fixture):
    transport, _, _ = ssh_fixture
    pty = await start(transport, "exec /bin/bash --noprofile --norc -i")
    program = ("import signal,time,sys;signal.alarm(15);"
               "signal.signal(signal.SIGINT,lambda *_:(print('INTERRUPTED',flush=True),sys.exit(130)));"
               "print('CHILD_READY',flush=True);time.sleep(10)")
    try:
        await pty.write(b"stty -echo; PS1=''; printf '\\123HELL_READY\\n'\r")
        await until(pty, b"SHELL_READY")
        await pty.write(("python3 -u -c " + shlex.quote(program)).encode() + b"\r")
        await until(pty, b"CHILD_READY")
        await pty.write(b"\x03")
        await until(pty, b"INTERRUPTED")
        await pty.write(b"printf '\\123HELL_STILL_ALIVE\\n'\r")
        await until(pty, b"SHELL_STILL_ALIVE")
        await pty.write(b"exit\r")
    finally:
        await pty.close()


async def test_remote_program_can_choose_raw_binary_mode(ssh_fixture):
    transport, _, _ = ssh_fixture
    data = bytes(range(256))
    program = ("import os,tty,signal;signal.alarm(15);tty.setraw(0);os.write(1,b'RAW_READY');data=b''\n"
               "while len(data)<256:data+=os.read(0,256-len(data))\n"
               "os.write(1,b'RAW_RESULT'+data+b'RAW_DONE')")
    pty = await start(transport, python_command(program))
    try:
        await until(pty, b"RAW_READY")
        await pty.write(data)
        output = await until(pty, b"RAW_DONE")
        assert b"RAW_RESULT" + data + b"RAW_DONE" in output
    finally:
        await pty.close()
