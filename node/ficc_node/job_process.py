# SPDX-License-Identifier: Apache-2.0
"""Drain output and stop child process groups before reaping their leaders."""

import os
import selectors
import signal
import time
from contextlib import suppress


def capture(proc, outputs, capacity, runtime_seconds, interrupted, settle=lambda: True):
    selector = selectors.DefaultSelector()
    counts = {"stdout": 0, "stderr": 0}
    dropped = 0
    reason = "exit"
    stop_at = None
    settled = False
    deadline = time.monotonic() + runtime_seconds
    try:
        for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while True:
            child = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            now = time.monotonic()
            if child is not None:
                # The leader stays unreaped until descendants in its group are stopped.
                with suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                if not settled:
                    if not settle():
                        raise ValueError("The service cgroup still has remaining processes.")
                    settled = True
                if not selector.get_map():
                    break
            elif stop_at is None and (interrupted() or now >= deadline):
                reason = "signal" if interrupted() else "runtime_limit"
                with suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGTERM)
                stop_at = now + 8
            elif stop_at is not None and now >= stop_at:
                with suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fd)
                    pipe = proc.stdout if key.data == "stdout" else proc.stderr
                    pipe.close()
                    continue
                available = max(0, capacity - sum(counts.values()))
                kept = chunk[:available]
                outputs[key.data].write(kept)
                counts[key.data] += len(kept)
                dropped += len(chunk) - len(kept)
        with suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        return proc.wait(), reason, counts, dropped
    finally:
        selector.close()
        for pipe in (proc.stdout, proc.stderr):
            if pipe:
                pipe.close()
        if proc.returncode is None:
            with suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
