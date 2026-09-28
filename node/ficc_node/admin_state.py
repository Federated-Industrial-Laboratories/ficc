# SPDX-License-Identifier: Apache-2.0
"""Retain bounded admin intents before mutation and never replay an identity."""

import fcntl
import os
import stat
from contextlib import contextmanager
from pathlib import Path

from . import admin_spec as spec
from .vm_state import checked_fd, read, write


def root():
    path = Path.home()
    for part in (".local", "state", "ficc", "admins"):
        path /= part
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise spec.ProviderError("admin_receipt_unavailable", "Receipt directories must be owned, direct and not writable by other accounts.")
    if path.stat().st_mode & 0o077:
        raise spec.ProviderError("admin_receipt_unavailable", "Administration receipt directories must have mode 0700.")
    return path


@contextmanager
def locked(profile):
    base = root()
    fd = checked_fd(base / (spec.identity(profile) + ".lock"), os.O_CREAT | os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise spec.ProviderError("admin_busy", "Another request is using this admin profile.") from exc
        yield base
    finally:
        os.close(fd)


def receipt(provider, request):
    params = request["parameters"]
    frozen = {key: request[key] for key in ("profile", "provider", "manager", "binding")}
    frozen["intent"] = params["intent"]
    checksum = spec.digest(frozen)
    with locked(request["profile"]) as base:
        path = base / f"{params['controller']}-{params['operation']}-{request['profile']}.json"
        if path.exists() or path.is_symlink():
            value = read(path)
            if value.get("digest") != checksum:
                raise spec.ProviderError("admin_idempotency", "The receipt identity belongs to another request.")
            if request["action"] == "forget":
                return forget(path, value, params["outcomes"])
            if any(item["state"] in {"observed", "resolved"} for item in value["results"]):
                raise spec.ProviderError("admin_cleanup_pending", "Receipt removal has started. Complete history removal in the host.")
            for item in value["results"]:
                if item["state"] == "dispatching":
                    item["state"] = "unknown"
                elif item["state"] == "queued":
                    item.update(state="refused", error=spec.error("admin_not_dispatched", "The request stopped before dispatch."))
            write(path, value)
            return value
        if request["action"] == "forget":
            return {"removed": True}
        if request["action"] == "receipt":
            raise spec.ProviderError("admin_receipt_missing", "The remote receipt is missing. The outcome remains unknown.")
        if sum(path.name.endswith(".json") for path in base.iterdir()) >= 1024:
            raise spec.ProviderError("admin_capacity", "The remote admin receipt limit is full.")
        value = {"digest": checksum, "results": [{"resource": item["resource"], "state": "queued"} for item in params["intent"]["expected"]]}
        write(path, value)
        for result in value["results"]:
            result["state"] = "dispatching"
        write(path, value)
        try:
            rows = provider.apply_batch(params["intent"]["action"], params["intent"]["expected"])
            if len(rows) != len(value["results"]) or any(row["resource"] != old["resource"] for row, old in zip(rows, value["results"], strict=True)):
                raise ValueError("The administration result identities changed.")
            value["results"] = rows
        except Exception:
            for result in value["results"]:
                result.update(state="unknown", error=spec.error("admin_outcome_unknown", "The provider action outcome is unknown."))
        write(path, value)
        return value


def forget(path, value, outcomes):
    rows = value.get("results")
    if not isinstance(rows, list) or len(rows) != len(outcomes):
        raise ValueError("Invalid admin receipt removal proof.")
    for row, outcome in zip(rows, outcomes, strict=True):
        state = row["state"]
        if row["resource"] != outcome["resource"] or not (
            state == outcome["state"] or outcome["state"] == "resolved" and state in {"accepted", "unknown", "dispatching"}
            or state == "accepted" and outcome["state"] == "observed"
            or state == "queued" and outcome["state"] == "refused"
        ):
            raise spec.ProviderError("admin_unresolved", "The node receipt has no matching terminal outcome or explicit owner resolution.")
    # Store terminal proof before unlink so an interrupted removal is retryable.
    value["results"] = outcomes
    write(path, value)
    path.unlink()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"removed": True}
