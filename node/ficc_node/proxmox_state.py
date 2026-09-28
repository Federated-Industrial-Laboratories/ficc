# SPDX-License-Identifier: Apache-2.0
"""Retain provider-bound Proxmox batch intent and exact asynchronous task IDs."""

import fcntl
import os
import stat
from contextlib import contextmanager

from . import proxmox_spec as spec
from . import vm_state as files
from .proxmox_compat import require_power
from .proxmox_process import run
from .vm_libvirt import ProviderError, error


@contextmanager
def locked():
    base = files.root() / "proxmox"
    base.mkdir(mode=0o700, exist_ok=True)
    info = base.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ProviderError("vm_receipt_unavailable", "The Proxmox receipt directory must be private and owned by this account.")
    fd = files.checked_fd(base / "lock", os.O_CREAT | os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProviderError("vm_busy", "Another Proxmox receipt request is active.") from exc
        yield base
    finally:
        os.close(fd)
def refresh(value, request):
    selected = [item for item in value["results"] if "task" in item and item["state"] == "accepted"]
    if selected:
        try:
            response = run({"action": "tasks", "parameters": {"upids": [item["task"]["upid"] for item in selected]}})
            spec.fields(response, {"tasks"})
            if not isinstance(response["tasks"], list) or len(response["tasks"]) != len(selected):
                raise ValueError("Invalid Proxmox task batch.")
            for item, task in zip(selected, response["tasks"], strict=True):
                spec.task(task, node=request["provider"]["node"], expected_vmid=spec.vmid(item["uuid"]),
                          action=request["parameters"]["intent"]["action"])
                if task["upid"] != item["task"]["upid"]:
                    raise ValueError("The Proxmox task identity changed.")
            for item, task in zip(selected, response["tasks"], strict=True):
                item["task"] = task
                if task["state"] == "stopped" and not spec.task_succeeded(task):
                    item.update(state="failed", error=error("vm_task_failed", "The provider task completed with an error."))
        except (ProviderError, ValueError):
            # Do not change accepted intent into a false failure when task
            # observation fails. Its exact UPID remains available for recovery.
            pass
    for item in value["results"]:
        if item["state"] == "dispatching":
            item["state"] = "unknown"
        elif item["state"] == "queued":
            item.update(state="refused", error=error("vm_not_dispatched", "The request stopped before provider dispatch."))


def receipt(request):
    params = request["parameters"]
    intent_digest = spec.digest({"connection": request["connection"], "profile": request["profile"],
                                "provider": request["provider"], "intent": params["intent"]})
    with locked() as base:
        path = base / (params["controller"] + "-" + params["operation"] + ".json")
        if path.exists() or path.is_symlink():
            value = files.read(path)
            if value.get("digest") != intent_digest:
                raise ProviderError("vm_idempotency_conflict", "The Proxmox receipt has a different frozen request.")
            if request["action"] == "forget":
                return forget(path, value, params["outcomes"])
            if any(item["state"] in {"observed", "resolved"} for item in value["results"]):
                raise ProviderError("vm_receipt_cleanup", "Receipt removal has started; retry removal.")
            else:
                refresh(value, request)
                files.write(path, value)
            return value
        if request["action"] == "forget":
            return {"removed": True}
        if request["action"] == "receipt":
            raise ProviderError("vm_receipt_missing", "The remote Proxmox receipt is missing; the outcome remains unknown.")
        require_power(request["provider"])
        if sum(1 for item in base.iterdir() if item.name.endswith(".json")) >= 1024:
            raise ProviderError("vm_receipt_capacity", "The remote Proxmox receipt limit is full.")
        value = {"digest": intent_digest, "results": [
            {"uuid": item["uuid"], "state": "dispatching"} for item in params["intent"]["expected"]]}
        files.write(path, value)
        try:
            response = run(request)
            spec.fields(response, {"results"})
            if len(response["results"]) != len(value["results"]):
                raise ValueError("Invalid Proxmox receipt length.")
            for expected, actual in zip(value["results"], response["results"], strict=True):
                spec.fields(actual, {"uuid", "state"}, {"task", "error"})
                if actual["uuid"] != expected["uuid"] or actual["state"] not in {"accepted", "unknown"}:
                    raise ValueError("Invalid Proxmox receipt identity.")
                if actual["state"] == "accepted":
                    spec.task(actual["task"], node=request["provider"]["node"], expected_vmid=spec.vmid(actual["uuid"]),
                              action=params["intent"]["action"])
            value["results"] = response["results"]
        except (ProviderError, ValueError, KeyError, TypeError):
            for item in value["results"]:
                item.update(state="unknown", error=error("vm_outcome_unknown", "The provider request outcome is unknown."))
        files.write(path, value)
        return value


def forget(path, value, outcomes):
    if len(value["results"]) != len(outcomes):
        raise ProviderError("vm_receipt_conflict", "The Proxmox cleanup batch does not match.")
    for item, outcome in zip(value["results"], outcomes, strict=True):
        state = item["state"]
        observed = (state == "accepted" and outcome["state"] == "observed"
                    and "task" in item and spec.task_succeeded(item["task"]))
        if "task" in item and item["task"]["state"] != "stopped":
            raise ProviderError("vm_task_active", "A running or unreadable provider task must retain its receipt.")
        valid = (state == outcome["state"] or observed
                 or outcome["state"] == "resolved" and state in {"accepted", "unknown", "dispatching"}
                 or state == "queued" and outcome["state"] == "refused")
        if item["uuid"] != outcome["uuid"] or not valid:
            raise ProviderError("vm_receipt_conflict", "The Proxmox terminal receipt proof does not match.")
    files.write(path, {"digest": value["digest"], "results": outcomes})
    path.unlink()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"removed": True}
