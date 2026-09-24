# SPDX-License-Identifier: Apache-2.0
"""Bound private per-agent files and atomic writes under a stable lock."""

import fcntl
import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

ID = re.compile(r"[0-9a-f]{32}\Z")
MAX_FILE = 32768
MAX_FILES = 1024
MAX_BYTES = 8 * 1024 * 1024
MAX_AGENTS = 512


def identity(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError("Invalid agent identity.")
    return value


def private(path):
    created = not path.exists()
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Agent directories must be private and owned by this account.")
    if created:
        sync(path.parent)
    return path


def root(controller):
    identity(controller)
    home = Path.home()
    for relative in (".local", ".local/state", ".local/state/ficc"):
        path = home / relative
        created = not path.exists()
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Agent parent directories must be owned real directories.")
        if created:
            sync(path.parent)
    return private(private(home / ".local/state/ficc/agents") / controller)


def base(controller, agent):
    parent = root(controller)
    identity(agent)
    target = parent / agent
    if (parent / ".archives" / agent).exists():
        raise ValueError("This agent identity is archived and cannot be launched or read as active.")
    if not target.exists() and sum(path.name != ".archives" for path in parent.iterdir()) >= MAX_AGENTS:
        raise ValueError("The retained agent namespace is full.")
    return private(target)


def checked_fd(path, flags=os.O_RDONLY):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
        os.close(fd)
        raise ValueError("Agent files must be private owned regular files with one link.")
    return fd


def read(path):
    fd = checked_fd(path)
    try:
        raw = os.read(fd, MAX_FILE + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_FILE:
        raise ValueError("Agent file exceeds capacity.")
    return json.loads(raw)


def sync(folder):
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(path, value):
    raw = json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":")).encode()
    if len(raw) > MAX_FILE:
        raise ValueError("Agent file exceeds capacity.")
    entries = [entry for entry in path.parent.iterdir() if not entry.name.startswith(".pending-")]
    current = sum(entry.lstat().st_size for entry in entries)
    replaced = path.lstat().st_size if path.exists() else 0
    if len(entries) + int(not path.exists()) > MAX_FILES or current - replaced + len(raw) > MAX_BYTES:
        raise ValueError("The agent spool capacity was reached.")
    scratch = path.with_name(".pending-" + path.name)
    if path.exists() or path.is_symlink():
        os.close(checked_fd(path))
    if scratch.exists() or scratch.is_symlink():
        os.close(checked_fd(scratch))
        scratch.unlink()
    fd = os.open(scratch, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(scratch, path)
        sync(path.parent)
    finally:
        if scratch.exists():
            scratch.unlink()


def inventory(folder):
    size = 0
    entries = list(folder.iterdir())
    if len(entries) > MAX_FILES * 2 or sum(not path.name.startswith(".pending-") for path in entries) > MAX_FILES:
        raise ValueError("The agent spool file limit was reached.")
    for path in entries:
        name = path.name.removeprefix(".pending-")
        if name not in {"lock", "spec.json", "runtime.json", "omp.ts"} and not re.fullmatch(r"(?:inbox|receipt|outbox|sent|rejected|rejection)-[a-f0-9]{32}\.json", name):
            raise ValueError("The agent spool contains an unknown file.")
        fd = checked_fd(path)
        try:
            length = os.fstat(fd).st_size
        finally:
            os.close(fd)
        if length > MAX_FILE:
            raise ValueError("An agent spool file exceeds capacity.")
        if not path.name.startswith(".pending-"):
            size += length
    if size > MAX_BYTES:
        raise ValueError("The agent spool byte limit was reached.")


@contextmanager
def locked(controller, agent):
    folder = base(controller, agent)
    path = folder / "lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("The agent lock is not private.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        inventory(folder)
        yield folder
    finally:
        os.close(fd)


def receipt(folder, delivery, state, detail=None, session_id=None):
    identity(delivery)
    value = {"id": delivery, "state": state, "detail": detail}
    if session_id is not None:
        value["session_id"] = session_id
    write(folder / ("receipt-" + delivery + ".json"), value)
    return value
