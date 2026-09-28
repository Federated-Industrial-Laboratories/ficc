# SPDX-License-Identifier: Apache-2.0
"""Run fixed service-manager programs with bounded output and process cleanup."""

import os
import selectors
import signal
import subprocess
import time
from pathlib import Path

from . import admin_spec as spec


def environment():
    uid = os.getuid()
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(Path.home()),
            "XDG_RUNTIME_DIR": f"/run/user/{uid}", "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus",
            "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0", "SYSTEMD_URLIFY": "0",
            "SYSTEMCTL_SKIP_AUTO_KEXEC": "1", "SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT": "1"}


def run(arguments, *, timeout=5, maximum=1048576, truncate=False):
    if arguments[0] not in {"/usr/bin/systemctl", "/usr/bin/busctl", "/usr/bin/journalctl"}:
        raise ValueError("The administration program is not permitted.")
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=environment(), start_new_session=True)
    assert process.stdout is not None and process.stderr is not None
    buffers = [bytearray(), bytearray()]
    deadline, clipped = time.monotonic() + timeout, False
    try:
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise spec.ProviderError("admin_timeout", "The service manager request exceeded its time limit.")
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    bound = maximum if key.data == 0 else 8192
                    remaining = bound - len(buffers[key.data])
                    buffers[key.data].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        if truncate and key.data == 0:
                            clipped = True
                            return 0, bytes(buffers[0]), True
                        raise spec.ProviderError("admin_output_limit", "The service manager response exceeded its byte limit.")
        return process.wait(timeout=max(0.01, deadline - time.monotonic())), bytes(buffers[0]), clipped
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
