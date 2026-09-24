# SPDX-License-Identifier: Apache-2.0
"""Confirm closed node work and enumerate exact archive member hashes."""

import shutil
import subprocess
import time
from pathlib import Path

from . import history_files as files
from . import job_system, terminals
from .job_spec import ID, RECEIPT_CAP, TERMINAL, TOTAL_LOG_CAP
from .job_state import checked, read


def job_closed(path, controller):
    request = read(path / "request.json")
    result = read(path / "result.json")
    identity = path.name
    unit = f"ficc-{controller}-{identity}.service"
    expected = f"FICC:{controller}:{identity}:{request['digest']}"
    if (request.get("controller_id") != controller or request.get("job_id") != identity
            or request.get("unit") != unit or request.get("description") != expected or result.get("state") not in TERMINAL):
        raise ValueError("A job identity or terminal receipt is invalid.")
    props = job_system.properties(unit)
    if props.get("LoadState") == "not-found":
        if props.get("Id", unit) != unit:
            raise ValueError("The absent unit identity is invalid.")
        return
    if (props.get("Id") != unit or props.get("Description") != expected
            or props.get("LoadState") not in {"loaded", "not-found"}
            or props.get("ActiveState") not in {"inactive", "failed"}):
        raise ValueError("A recorded job unit is active, unknown, or has another identity.")
    group = props.get("ControlGroup", "")
    if group:
        path = Path("/sys/fs/cgroup") / group.lstrip("/")
        if ".." in path.parts or path.name != unit:
            raise ValueError("The recorded job cgroup identity is invalid.")
        if path.exists() and "populated 1" in (path / "cgroup.events").read_text().splitlines():
            raise ValueError("The recorded job still has processes.")


def no_tmux(controller):
    if not shutil.which("tmux"):
        raise ValueError("tmux is required to verify that the terminal namespace is absent.")
    result = subprocess.run(terminals.command(controller, "list-sessions", "-F", "#{session_id}"),
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=5, check=False)
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise ValueError("The terminal namespace response exceeds the limit.")
    if result.returncode == 0:
        raise ValueError("The terminal namespace still has live sessions.")
    diagnostic = result.stderr.decode(errors="replace").lower()
    if result.returncode != 1 or not any(message in diagnostic for message in ("no server running", "no such file or directory")):
        raise ValueError("The terminal namespace could not be verified as absent.")


def scan(bases, request):
    members = {}
    deadline = time.monotonic() + 300
    jobs = files.entries(bases["jobs"], RECEIPT_CAP + 2)
    for name in jobs:
        if name in {"lock", "controller.json"}:
            checked(bases["jobs"] / name)
            continue
        if not ID.fullmatch(name):
            raise ValueError("The job namespace contains unexpected state.")
        path = bases["jobs"] / name
        names = files.entries(path, 8)
        if not {"request.json", "result.json"}.issubset(names) or not set(names).issubset(files.JOB_FILES):
            raise ValueError("The job receipt is incomplete or has unexpected files.")
        job_closed(path, request["controller_id"])
        for filename in names:
            key = "jobs/" + name + "/" + filename
            members[key] = files.fingerprint(path / filename, files.maximum(key), deadline)
    for kind, cap, lock in (("files", 4096, "namespace.lock"), ("terminals", 512, "lock")):
        for name in files.entries(bases[kind], cap + 1):
            if name == lock:
                checked(bases[kind] / name)
                continue
            if not name.endswith(".json") or not ID.fullmatch(name[:-5]):
                raise ValueError("The receipt namespace contains unexpected state.")
            value = read(bases[kind] / name, 262144 if kind == "files" else 131072)
            allowed = {"succeeded", "cancelled"} if kind == "files" else {"stopped"}
            if value.get("id") != name[:-5] or value.get("state") not in allowed or value.get("cleanup_pending"):
                raise ValueError("A file or terminal receipt is active, unknown, or requires cleanup.")
            key = kind + "/" + name
            members[key] = files.fingerprint(bases[kind] / name, files.maximum(key), deadline)
    no_tmux(request["terminal_controller"])
    logs = sum(value["size"] for name, value in members.items() if name.endswith(("/stdout", "/stderr")))
    if len(members) > files.MAX_MEMBERS or sum(value["size"] for value in members.values()) > files.MAX_BYTES or logs > TOTAL_LOG_CAP:
        raise ValueError("Retained history exceeds the supported archive limit.")
    return members
