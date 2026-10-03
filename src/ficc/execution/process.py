# SPDX-License-Identifier: Apache-2.0
"""Bound administrator command replies without retaining workload output in memory."""

import os
import selectors
import subprocess
import time

ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


def command(argv, *, timeout=5, okay=(0,)):
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=ENVIRONMENT, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    for name in output:
        pipe = getattr(process, name)
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise ValueError("An administrator command did not complete within its control bound.")
            for key, _ in selector.select(min(0.02, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    getattr(process, key.data).close()
                    continue
                output[key.data].extend(chunk)
                if sum(map(len, output.values())) > 65536:
                    raise ValueError("An administrator command exceeded its diagnostic bound.")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code not in okay:
            raise ValueError("An administrator command failed. Inspect the local service state.")
        return {"exit": code, **{key: bytes(value).decode("utf-8", errors="replace") for key, value in output.items()}}
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, 9)
            process.wait()
        for name in output:
            getattr(process, name).close()


def properties(unit, names):
    result = command(["/usr/bin/systemctl", "show", unit, "--no-pager",
                      "--property=" + ",".join(names)])
    values: dict[str, str] = {}
    for line in result["stdout"].splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name in values:
            if name != "DeviceAllow":
                raise ValueError("An administrator command repeated a scalar property.")
            value = values[name] + " " + value
        values[name] = value
    return values
