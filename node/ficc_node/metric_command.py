# SPDX-License-Identifier: Apache-2.0
"""Run fixed observation commands with bounded output and execution time."""

import os
import selectors
import subprocess
import time


def read_command(command: list[str], maximum: int = 65536, timeout: float = 3) -> bytes:
    output = bytearray()
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env={**os.environ, "LC_ALL": "C"}) as process:
        assert process.stdout is not None
        try:
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("Metric query timed out.")
                    for key, _ in selector.select(min(0.1, remaining)):
                        block = os.read(key.fd, 8192)
                        if not block:
                            selector.unregister(key.fileobj)
                        output.extend(block)
                        if len(output) > maximum:
                            raise ValueError("Metric output exceeds the limit.")
            if process.wait(timeout=max(0.001, deadline - time.monotonic())):
                raise ValueError("Metric query failed.")
            return bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
