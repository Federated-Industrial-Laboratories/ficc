# SPDX-License-Identifier: Apache-2.0
"""Serialize file actions and retain private durable node receipts."""

import fcntl
import os
import re
from contextlib import contextmanager
from pathlib import Path

from .file_access import FileError
from .job_state import directory, read, write

ID = re.compile(r"[a-f0-9]{32}\Z")


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise FileError("invalid_identity", "The operation identity is invalid.")
    return value


def state_root(state_dir=None):
    path = Path(state_dir) if state_dir else Path.home() / ".local/state/ficc/files"
    for parent in path.parents:
        if parent.exists() and parent.is_symlink():
            raise FileError("invalid_state", "The file state parent cannot be a link.")
    return directory(path)


@contextmanager
def locked(request, state_dir=None):
    base = state_root(state_dir)
    controller = identifier(request["controller_id"])
    identifier(request["root"]["id"])
    folder = directory(base / controller)
    lock = os.open(folder / "namespace.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield folder
    finally:
        os.close(lock)


def record_path(base, value):
    return base / (identifier(value) + ".json")


def load(base, value):
    path = record_path(base, value)
    return read(path, 262144) if path.exists() else None


def save(base, value):
    path = record_path(base, value["id"])
    if not path.exists() and sum(1 for _ in base.glob("*.json")) >= 4096:
        raise FileError("capacity", "The retained file operation limit was reached.")
    write(path, value)
