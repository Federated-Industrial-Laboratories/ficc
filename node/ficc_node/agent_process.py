# SPDX-License-Identifier: Apache-2.0
"""Bound version probes and reap owned process groups after their descendants."""

import os
import selectors
import signal
import subprocess
import time
from contextlib import suppress


def alive(process):
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None


def stop_group(process):
    # The child leader remains unreaped, so its group identifier cannot be reused.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + 2
    while alive(process) and time.monotonic() < deadline:
        time.sleep(0.02)
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=3)


def version(argv):
    process = subprocess.Popen([*argv, "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = bytearray()
    try:
        assert process.stdout is not None
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if selector.select(0.1):
                data = os.read(process.stdout.fileno(), 4097)
                if not data:
                    break
                output.extend(data)
                if len(output) > 4096:
                    raise ValueError("The agent version output exceeds capacity.")
        else:
            raise ValueError("The agent version check timed out.")
        result = None
        while time.monotonic() < deadline:
            result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result is not None:
                break
            time.sleep(0.02)
        if result is None:
            raise ValueError("The agent version process did not exit.")
        if result.si_code != os.CLD_EXITED or result.si_status != 0:
            raise ValueError("The agent version check failed.")
        return output.decode("utf-8", "replace").strip()
    finally:
        stop_group(process)
        selector.close()
        if process.stdout:
            process.stdout.close()
