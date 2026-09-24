# SPDX-License-Identifier: Apache-2.0
"""Admit, inspect, and cancel recorded systemd jobs without shell expansion."""

import base64
import hashlib
import os
import sys
import time
from contextlib import suppress
from pathlib import Path

from . import job_state as state
from .collect import gpu_metrics
from .job_spec import ID, LOG_CAP, RECEIPT_CAP, TERMINAL, TOTAL_LOG_CAP, validate_job
from .job_system import capability, command, properties, start


def identity(request, props):
    if props.get("LoadState") == "not-found":
        return False
    if props.get("Id") != request["unit"] or props.get("Description") != request["description"]:
        raise ValueError("The unit identity does not match the saved job.")
    return True


def snapshot(path):
    request = state.read(path / "request.json")
    result = {"job_id": request["job_id"], "state": "unknown", "result": None,
              "effective_limits": None, "session_lifetime": request["session_lifetime"],
              "reservations": request["reservations"], "error": None}
    if (path / "started.json").exists():
        result["effective_limits"] = state.read(path / "started.json")["effective_limits"]
    if (path / "result.json").exists():
        result.update(state.read(path / "result.json"))
        # The durable receipt permits removal of the retained unit result.
        with suppress(OSError, ValueError):
            props = properties(request["unit"])
            if identity(request, props):
                command(["systemctl", "--user", "stop", "--no-block", request["unit"]])
                command(["systemctl", "--user", "reset-failed", request["unit"]])
        return result
    if request["boot_id"] != state.boot_id():
        terminal: dict = {"state": "interrupted", "result": {"exit_code": None, "signal": None,
                    "reason": "node_reboot", "stdout_bytes": None, "stderr_bytes": None,
                    "dropped_bytes": None, "finished_at": None}}
        state.write(path / "result.json", terminal)
        result.update(terminal)
        return result
    props = properties(request["unit"])
    if not identity(request, props):
        saved_error = path / "launch_error.json"
        result["error"] = state.read(saved_error)["message"] if saved_error.exists() else "No unit or result confirms the launch outcome."
        return result
    if props.get("ActiveState") in {"active", "activating", "deactivating"}:
        result["state"] = "cancel_requested" if (path / "cancel.json").exists() else "running"
        return result
    cgroup = props.get("ControlGroup", "")
    if cgroup:
        group = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
        if group.name != request["unit"]:
            raise ValueError("The recorded service cgroup identity changed.")
        if group.exists() and "populated 1" in (group / "cgroup.events").read_text().splitlines():
            result["error"] = "The job service still has remaining processes."
            return result
    code = int(props.get("ExecMainCode", "0"))
    status = int(props.get("ExecMainStatus", "0"))
    terminal = {"state": "cancelled" if (path / "cancel.json").exists() else "failed",
                "result": {"exit_code": status if code == 1 else None,
                           "signal": status if code in (2, 3) else None,
                           "reason": "systemd_" + props.get("Result", "unknown"),
                           "stdout_bytes": None, "stderr_bytes": None,
                           "dropped_bytes": None, "finished_at": None}}
    if props.get("Result") == "success":
        terminal["state"] = "interrupted"
        terminal["result"]["reason"] = "runner_receipt_missing"
    state.write(path / "result.json", terminal)
    result.update(terminal)
    return result


def pin_runner(path):
    source = Path(sys.argv[0])
    if not source.is_file() or source.stat().st_size > 1048576:
        raise ValueError("A packaged helper is required for managed jobs.")
    data = source.read_bytes()
    name = path / "runner.pyz"
    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return name, hashlib.sha256(data).hexdigest()


def recover_prelaunch(controller):
    for entry in state.root().iterdir():
        if entry.name.startswith(".pending-") and ID.fullmatch(entry.name.removeprefix(".pending-")):
            # The fixed runner can only open published, opaque job directories.
            state.discard_prelaunch(entry, request_allowed=True)
        elif ID.fullmatch(entry.name) and not (entry / "request.json").exists():
            state.prelaunch_files(entry)
            unit = f"ficc-{controller}-{entry.name}.service"
            if properties(unit).get("LoadState") != "not-found":
                raise ValueError("An incomplete job record has a retained unit. Explicit recovery is required.")
            state.discard_prelaunch(entry)


def submit(body):
    job = validate_job(body["job"])
    path = state.job_path(body["job_id"])
    recover_prelaunch(body["controller_id"])
    digest = state.digest({"job": job, "node_id": body["node_id"]})
    if path.exists():
        old = state.read(path / "request.json")
        if old["digest"] != digest or old["controller_id"] != body["controller_id"]:
            raise ValueError("The job identity has a different request.")
        return snapshot(path)
    caps = capability()
    if not caps["jobs"]:
        raise ValueError(caps.get("job_error", "Managed jobs are unavailable."))
    if not caps["logout_persistent"] and not job["allow_session_lifetime"]:
        raise ValueError("This node requires explicit session lifetime acceptance.")
    existing = [entry for entry in state.root().iterdir() if entry.is_dir()]
    if len(existing) >= RECEIPT_CAP:
        raise ValueError("Retained job receipt capacity is full.")
    reserved_bytes = 0
    busy = False
    for entry in existing:
        receipt = entry / "result.json"
        status = state.read(receipt) if receipt.exists() else snapshot(entry)
        if status["state"] not in TERMINAL:
            busy = True
            reserved_bytes += LOG_CAP
        else:
            for stream in ("stdout", "stderr"):
                output = entry / stream
                if output.exists() or output.is_symlink():
                    reserved_bytes += state.checked(output).stat().st_size
    if reserved_bytes + LOG_CAP > TOTAL_LOG_CAP:
        raise ValueError("Retained job output capacity is full.")
    if busy:
        raise ValueError("Another job is active or has an unknown outcome.")
    reservations = job["gpu_reservations"].get(body["node_id"], [])
    if reservations:
        gpus, _ = gpu_metrics()
        devices = {gpu["uuid"]: gpu for gpu in gpus}
        for reservation in reservations:
            gpu = devices.get(reservation["uuid"])
            if gpu is None or gpu["memory_total_bytes"] is None or gpu["memory_used_bytes"] is None:
                raise ValueError("GPU capacity cannot be verified.")
            if reservation["memory_bytes"] > gpu["memory_total_bytes"] - gpu["memory_used_bytes"]:
                raise ValueError("The GPU reservation exceeds observed free memory.")
    with state.staging(path) as temporary:
        _, runner_digest = pin_runner(temporary)
        request = {"controller_id": body["controller_id"], "job_id": body["job_id"],
                   "job": job, "digest": digest, "boot_id": state.boot_id(), "runner_digest": runner_digest,
                   "unit": f'ficc-{body["controller_id"]}-{body["job_id"]}.service',
                   "description": f'FICC:{body["controller_id"]}:{body["job_id"]}:{digest}',
                   "session_lifetime": not caps["logout_persistent"], "reservations": reservations,
                   "created_at": time.time()}
        state.write(temporary / "request.json", request)
        state.publish(temporary, path)
    try:
        start(request, path / "runner.pyz")
    except (OSError, ValueError) as exc:
        # A saved intent is never resubmitted after an ambiguous acknowledgement.
        state.write(path / "launch_error.json", {"message": str(exc)[:256]})
        return {"job_id": body["job_id"], "state": "unknown", "result": None,
                "effective_limits": None, "error": str(exc)[:256],
                "session_lifetime": request["session_lifetime"], "reservations": reservations}
    return snapshot(path)


def dispatch(body):
    action = body.get("action")
    if body.get("version") != "2":
        raise ValueError("Unsupported job protocol.")
    if action == "job.capabilities":
        if set(body) != {"version", "action"}:
            raise ValueError("Invalid capability fields.")
        return capability()
    fields = {"version", "action", "controller_id", "job_id"}
    fields |= {"job", "node_id"} if action == "job.submit" else {"force"} if action == "job.cancel" else {"stream", "offset", "limit"} if action == "job.logs" else set()
    if set(body) != fields or action not in {"job.submit", "job.status", "job.cancel", "job.logs"}:
        raise ValueError("Unsupported job action or fields.")
    if action == "job.logs":
        validate_log_request(body)
    with state.locked(body["controller_id"]):
        if action == "job.submit":
            return submit(body)
        path = state.job_path(body["job_id"])
        if not path.exists():
            if action == "job.logs":
                return {"data_base64": "", "next_offset": body["offset"], "total_bytes": 0,
                        "dropped_bytes": None, "complete": False}
            return {"job_id": body["job_id"], "state": "unknown", "result": None,
                    "error": "No retained request confirms this job."}
        request = state.read(path / "request.json")
        if request["controller_id"] != body["controller_id"]:
            raise ValueError("Invalid controller identity.")
        if action == "job.status":
            return snapshot(path)
        if action == "job.cancel":
            if type(body["force"]) is not bool:
                raise ValueError("Invalid cancellation choice.")
            status = snapshot(path)
            if status["state"] in TERMINAL:
                return status
            state.write(path / "cancel.json", {"at": time.time(), "force": body["force"]})
            if identity(request, properties(request["unit"])):
                if body["force"]:
                    command(["systemctl", "--user", "kill", "--kill-whom=all", "--signal=SIGKILL", request["unit"]])
                else:
                    command(["systemctl", "--user", "stop", "--no-block", request["unit"]])
            return snapshot(path)
        return logs(path, body)


def validate_log_request(body):
    if not isinstance(body["stream"], str) or body["stream"] not in {"stdout", "stderr"}:
        raise ValueError("Invalid output stream.")
    if type(body["offset"]) is not int or not 0 <= body["offset"] <= 2**63 - 1:
        raise ValueError("Invalid output offset.")
    if type(body["limit"]) is not int or not 1 <= body["limit"] <= 65536:
        raise ValueError("Invalid output limit.")


def logs(path, body):
    validate_log_request(body)
    file = path / body["stream"]
    data, total = b"", 0
    if file.exists():
        state.checked(file)
        with file.open("rb") as stream:
            total = os.fstat(stream.fileno()).st_size
            stream.seek(body["offset"])
            data = stream.read(body["limit"])
    result = state.read(path / "result.json") if (path / "result.json").exists() else None
    return {"data_base64": base64.b64encode(data).decode(), "next_offset": body["offset"] + len(data),
            "total_bytes": total, "dropped_bytes": result["result"].get("dropped_bytes") if result else None,
            "complete": result is not None}
