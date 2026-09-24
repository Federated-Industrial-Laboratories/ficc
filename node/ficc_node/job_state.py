# SPDX-License-Identifier: Apache-2.0
"""Keep private requests and atomic receipts for managed jobs."""

import fcntl
import hashlib
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .job_spec import ID


def directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Job directories must be private and owned by this account.")
    return path


def root():
    home = Path.home()
    path = home / ".local/state/ficc/jobs"
    for parent in (home / ".local", home / ".local/state", home / ".local/state/ficc"):
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("Job parent directories must belong to this account and must not be links.")
    return directory(path)


def checked(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Job files must be private and owned by this account.")
    return path


def read(path, maximum=131072):
    checked(path)
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("Job record exceeds the limit.")
    return json.loads(raw)


def write(path, value):
    if path.exists() or path.is_symlink():
        checked(path)
    data = json.dumps(value, allow_nan=False, sort_keys=True).encode()
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(sync)
        finally:
            os.close(sync)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def job_path(job_id):
    if not isinstance(job_id, str) or not ID.fullmatch(job_id):
        raise ValueError("Invalid job identity.")
    path = root() / job_id
    if path.exists() or path.is_symlink():
        directory(path)
    return path


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


@contextmanager
def locked(controller):
    if not isinstance(controller, str) or not ID.fullmatch(controller):
        raise ValueError("Invalid controller identity.")
    base = root()
    fd = os.open(base / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        checked(base / "lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        owner = base / "controller.json"
        if owner.exists():
            if read(owner) != {"id": controller}:
                raise ValueError("This node job namespace belongs to another controller.")
        else:
            write(owner, {"id": controller})
        yield
    finally:
        os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prelaunch_files(path, request_allowed=False):
    directory(path)
    entries = list(path.iterdir())
    allowed = {"runner.pyz", "request.json"} if request_allowed else {"runner.pyz"}
    if len(entries) > 8 or any(entry.name not in allowed and not entry.name.startswith(".write-") for entry in entries):
        raise ValueError("Incomplete job state requires explicit recovery.")
    for entry in entries:
        checked(entry)
    return entries


def discard_prelaunch(path, request_allowed=False):
    for entry in prelaunch_files(path, request_allowed):
        entry.unlink()
    path.rmdir()
    sync_directory(path.parent)


@contextmanager
def staging(path):
    temporary = path.parent / (".pending-" + path.name)
    temporary.mkdir(mode=0o700)
    try:
        yield temporary
    finally:
        if temporary.exists() or temporary.is_symlink():
            discard_prelaunch(temporary, request_allowed=True)


def publish(temporary, path):
    if path.exists() or path.is_symlink():
        raise ValueError("A job record already uses this identity.")
    os.rename(temporary, path)
    sync_directory(path.parent)
