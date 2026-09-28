# SPDX-License-Identifier: Apache-2.0
"""Write lifecycle intent before dispatch and never repeat a receipt identity."""

import fcntl
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .vm_libvirt import ProviderError, error
from .vm_spec import decode, digest, encode


def root():
    path = Path.home()
    for part in (".local", "state", "ficc", "vm"):
        path = path / part
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ProviderError("vm_receipt_unavailable", "VM receipt ancestors must be owned by this account, without links or group/world write access.")
    if path.stat().st_mode & 0o077:
        raise ProviderError("vm_receipt_unavailable", "The VM receipt directory must have mode 0700.")
    return path


def checked_fd(path, flags):
    fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        os.close(fd)
        raise ProviderError("vm_receipt_unavailable", "VM receipt files must be private, regular and owned by this account, without extra links.")
    return fd


def read(path):
    fd = checked_fd(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as stream:
        return decode(stream.read(1024 * 1024 + 1))


def write(path, value):
    if path.exists() or path.is_symlink():
        os.close(checked_fd(path, os.O_RDONLY))
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encode(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(sync)
        finally:
            os.close(sync)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def locked():
    base = root()
    fd = checked_fd(base / "lock", os.O_CREAT | os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProviderError("vm_busy", "Another VM receipt request is active.") from exc
        yield base
    finally:
        os.close(fd)


def receipt(provider, request):
    params = request["parameters"]
    identity = {key: request[key] for key in ("connection", "profile")}
    identity["intent"] = params["intent"]
    intent_digest = digest(identity)
    with locked() as base:
        path = base / (params["controller"] + "-" + params["operation"] + ".json")
        if path.exists() or path.is_symlink():
            value = read(path)
            if value.get("digest") != intent_digest:
                raise ProviderError("vm_idempotency_conflict", "The receipt identity has a different request.")
            if request["action"] == "forget":
                return forget(path, value, params["outcomes"])
            if any(item["state"] in {"observed", "resolved"} for item in value["results"]):
                raise ProviderError("vm_receipt_cleanup", "Receipt removal has started; retry removal.")
            for item in value["results"]:
                if item["state"] == "dispatching":
                    item["state"] = "unknown"
                elif item["state"] == "queued":
                    item["state"] = "refused"
                    item["error"] = error("vm_not_dispatched", "The request stopped before this VM was dispatched.")
            write(path, value)
            return value
        if request["action"] == "forget":
            return {"removed": True}
        if request["action"] == "receipt":
            raise ProviderError("vm_receipt_missing", "The remote receipt is missing; the outcome remains unknown.")
        if sum(1 for item in base.iterdir() if item.name.endswith(".json")) >= 1024:
            raise ProviderError("vm_receipt_capacity", "The remote VM receipt limit is full.")
        value = {"digest": intent_digest, "results": [
            {"uuid": item["uuid"], "state": "queued"} for item in params["intent"]["expected"]]}
        write(path, value)
        for result, expected in zip(value["results"], params["intent"]["expected"], strict=True):
            result["state"] = "dispatching"
            write(path, value)
            try:
                result.update(provider.apply(params["intent"]["action"], expected))
            except Exception:
                result.update(state="unknown", error=error("vm_outcome_unknown", "The provider request outcome is unknown."))
            write(path, value)
        return value


def forget(path, value, outcomes):
    if len(value["results"]) != len(outcomes):
        raise ProviderError("vm_receipt_conflict", "The receipt cleanup batch does not match.")
    for item, outcome in zip(value["results"], outcomes, strict=True):
        state = item["state"]
        valid = (state == outcome["state"]
                 or outcome["state"] == "resolved" and state in {"accepted", "unknown", "dispatching"}
                 or state == "accepted" and outcome["state"] == "observed"
                 or state == "queued" and outcome["state"] == "refused")
        if item["uuid"] != outcome["uuid"] or not valid:
            raise ProviderError("vm_receipt_conflict", "The receipt cleanup identity or terminal proof does not match.")
    value["results"] = outcomes
    write(path, value)
    path.unlink()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"removed": True}
