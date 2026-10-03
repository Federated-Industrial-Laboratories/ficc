# SPDX-License-Identifier: Apache-2.0
"""Detect lost final console bytes and unbounded half-closed stream lifetimes."""

import os
import selectors
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager

import pytest


@contextmanager
def process_pair(seconds=2):
    parent, child = socket.socketpair()
    parent.settimeout(3)
    process = subprocess.Popen([sys.executable, "-c",
        "import sys;from ficc_node.vm_console import relay;relay(int(sys.argv[1]),float(sys.argv[2]))",
        str(child.fileno()), str(seconds)], pass_fds=(child.fileno(),),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    child.close()
    try:
        yield process, parent
    finally:
        parent.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def output(process):
    result = bytearray()
    deadline = time.monotonic() + 4
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            assert selector.select(max(0, deadline - time.monotonic())), "The console relay did not terminate."
            data = os.read(process.stdout.fileno(), 65536)
            if not data:
                return bytes(result)
            result.extend(data)
            assert len(result) <= 131072


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_provider_eof_drains_last_bounded_response(size):
    with process_pair() as (process, provider):
        payload = bytes(range(255)) * (4 * size) + b"RFB-final"
        assert os.write(provider.fileno(), payload) == len(payload)
        provider.close()
        assert output(process) == payload
        assert process.wait(timeout=3) == 0


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_input_bytes_precede_provider_eof_and_cancel_stays_prompt(size):
    with process_pair() as (process, provider):
        payload = b"input" * size
        process.stdin.write(payload)
        process.stdin.flush()
        received = bytearray()
        while len(received) < len(payload):
            received.extend(provider.recv(len(payload) - len(received)))
        assert bytes(received) == payload
        process.stdin.close()
        assert process.wait(timeout=1) == 0


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_blocked_output_cannot_extend_deadline(size):
    with process_pair(.2) as (process, provider):
        payload = b"x" * (2048 * size)
        assert os.write(provider.fileno(), payload) == len(payload)
        provider.close()
        assert process.wait(timeout=1) == 0
