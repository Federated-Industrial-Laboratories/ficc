# SPDX-License-Identifier: Apache-2.0
"""Execute a saved job with verified limits and bounded output."""

import hashlib
import os
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path

from . import job_state as state
from .job_process import capture
from .job_spec import LOG_CAP
from .job_system import settle, verify


def run(job_id):
    path = state.job_path(job_id)
    request = state.read(path / "request.json")
    runner = state.checked(path / "runner.pyz")
    if hashlib.sha256(runner.read_bytes()).hexdigest() != request["runner_digest"]:
        return 1
    if request["job_id"] != job_id or request["boot_id"] != state.boot_id():
        return 1
    if (path / "result.json").exists():
        return 0
    counts = {"stdout": 0, "stderr": 0}
    dropped = 0
    result: dict = {"exit_code": None, "signal": None, "reason": "runner_error"}
    proc = None
    interrupted = False

    def stop(signum, frame):
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        effective = verify(request["job"]["limits"], request["unit"])
        state.write(path / "started.json", {"at": time.time(), "effective_limits": effective})
        job = request["job"]
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(Path.home()),
               "LANG": "C.UTF-8", **job["env"],
               "CUDA_VISIBLE_DEVICES": ",".join(gpu["uuid"] for gpu in request["reservations"])}
        proc = subprocess.Popen(job["argv"], cwd=job["cwd"] or str(Path.home()), env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        outputs = {}
        try:
            for name in ("stdout", "stderr"):
                fd = os.open(path / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                outputs[name] = os.fdopen(fd, "wb", buffering=0)
            code, reason, counts, dropped = capture(proc, outputs, LOG_CAP,
                                                    job["limits"]["runtime_seconds"], lambda: interrupted,
                                                    lambda: settle(request["unit"]))
            if reason == "signal" and (path / "cancel.json").exists():
                reason = "cancelled"
            result.update(exit_code=code if code >= 0 else None,
                          signal=-code if code < 0 else None, reason=reason)
        finally:
            for output in outputs.values():
                output.flush()
                os.fsync(output.fileno())
                output.close()
    except (OSError, ValueError, subprocess.SubprocessError):
        result["reason"] = "required_limit_or_runner_failure"
    finally:
        if proc is not None and proc.returncode is None:
            with suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    if proc is not None:
        try:
            if not settle(request["unit"]):
                return 1
        except (OSError, ValueError):
            return 1
    cancelled = result["reason"] == "cancelled" or (
        result["signal"] is not None and (path / "cancel.json").exists())
    status = "cancelled" if cancelled else "succeeded" if result["exit_code"] == 0 and result["reason"] == "exit" else "failed"
    result.update(stdout_bytes=counts["stdout"], stderr_bytes=counts["stderr"], dropped_bytes=dropped,
                  finished_at=time.time())
    state.write(path / "result.json", {"state": status, "result": result})
    return 0
