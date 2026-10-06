# SPDX-License-Identifier: Apache-2.0
"""Bound version probes and reap owned process groups after their descendants."""

import os
import selectors
import signal
import subprocess
import time
from contextlib import suppress

from ficc.posix_host import kill_group, process_descriptor


def alive(process):
    if process.returncode is not None:
        return False
    descriptor = process_descriptor(process.pid)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            return not selector.select(0)
    finally:
        os.close(descriptor)


def stop_group(process):
    if process.returncode is not None:
        return
    # The child leader remains unreaped, so its group identifier cannot be reused.
    try:
        with suppress(ProcessLookupError):
            kill_group(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + 2
        while alive(process) and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        with suppress(ProcessLookupError):
            kill_group(process.pid)
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
        while time.monotonic() < deadline:
            if not alive(process):
                break
            time.sleep(0.02)
        else:
            raise ValueError("The agent version process did not exit.")
    finally:
        try:
            stop_group(process)
        finally:
            selector.close()
            if process.stdout:
                process.stdout.close()
    if process.returncode != 0:
        raise ValueError("The agent version check failed.")
    return output.decode("utf-8", "replace").strip()
