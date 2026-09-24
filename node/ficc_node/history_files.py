# SPDX-License-Identifier: Apache-2.0
"""Validate and move bounded immutable history members without replacing paths."""

import hashlib
import os
import re
import stat
import time
from pathlib import Path

from .file_access import rename
from .history_write import persist
from .job_spec import LOG_CAP
from .job_state import directory, sync_directory

MAX_MANIFEST = 4 * 1024**2
MAX_MEMBERS = 8192
MAX_BYTES = 4 * 1024**3
ID = r"[a-f0-9]{32}"
JOB_FILES = {"request.json", "result.json", "started.json", "cancel.json", "launch_error.json", "runner.pyz", "stdout", "stderr"}


def maximum(name):
    parts = name.split("/")
    if len(parts) == 3 and parts[0] == "jobs" and re.fullmatch(ID, parts[1]) and parts[2] in JOB_FILES:
        return LOG_CAP if parts[2] in {"stdout", "stderr"} else 1048576 if parts[2] == "runner.pyz" else 131072
    if len(parts) == 2 and parts[0] in {"files", "terminals"} and re.fullmatch(ID + r"\.json", parts[1]):
        return 262144 if parts[0] == "files" else 131072
    raise ValueError("The history member path is invalid.")


def fingerprint(path, limit, deadline=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o077
                or before.st_nlink != 1 or before.st_size > limit):
            raise ValueError("History files must be bounded private regular files without links.")
        size, digest = 0, hashlib.sha256()
        while data := os.read(fd, 262144):
            size += len(data)
            if size > limit or (deadline and time.monotonic() > deadline):
                raise ValueError("History verification exceeds its size or time limit.")
            digest.update(data)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("A history file changed during verification.")
        return {"size": size, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def entries(path, count):
    directory(path)
    with os.scandir(path) as scan:
        result = []
        for item in scan:
            result.append(item.name)
            if len(result) > count:
                raise ValueError("The history entry count exceeds its limit.")
    return sorted(result)


def verify_group(path, group, members, deadline):
    expected = {name: detail for name, detail in members.items() if name == group or name.startswith(group + "/")}
    if group.startswith("jobs/"):
        actual = {group + "/" + name for name in entries(path, 8)}
        if actual != set(expected):
            raise ValueError("A job archive has missing or unexpected members.")
        for name, detail in expected.items():
            if fingerprint(path / Path(name).name, maximum(name), deadline) != detail:
                raise ValueError("A job history hash does not match.")
    elif expected.get(group) != fingerprint(path, maximum(group), deadline):
        raise ValueError("A history receipt hash does not match.")


def groups(members):
    return sorted({"/".join(name.split("/")[:2]) if name.startswith("jobs/") else name for name in members})


def move(source, target):
    directory(target.parent)
    persist(target.parent, target.parent.parent)
    source_fd = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    target_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        rename(source_fd, os.fsencode(source.name), target_fd, os.fsencode(target.name))
        os.fsync(source_fd)
        os.fsync(target_fd)
    finally:
        os.close(target_fd)
        os.close(source_fd)


def move_groups(bases, archive, members):
    deadline = time.monotonic() + 300
    for group in groups(members):
        kind, name = group.split("/", 1)
        source, target = bases[kind] / name, archive / group
        source_exists = source.exists() or source.is_symlink()
        target_exists = target.exists() or target.is_symlink()
        if source_exists == target_exists:
            raise ValueError("History publication has a missing or duplicated receipt; explicit recovery is required.")
        if source_exists:
            verify_group(source, group, members, deadline)
            move(source, target)
        verify_group(target, group, members, deadline)
    sync_directory(archive)
