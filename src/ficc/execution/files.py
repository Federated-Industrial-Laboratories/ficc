# SPDX-License-Identifier: Apache-2.0
"""Keep executor files bounded, durable, and below their recorded directories."""

import hashlib
import json
import os
import secrets
import stat
from pathlib import Path

from .spec import encoded


def directory(path: Path, *, owner=0, private=False):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in {0, owner} or info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                raise ValueError("An executor directory has another owner or shared write access.")
        info = os.fstat(fd)
        if info.st_uid != owner or private and info.st_mode & 0o077:
            raise ValueError("The executor directory ownership or private mode differs.")
        return info
    finally:
        os.close(fd)


def atomic(path: Path, value, mode=0o600):
    atomic_bytes(path, encoded(value), mode)


def atomic_bytes(path: Path, data: bytes, mode=0o600):
    if len(data) > 1024 * 1024:
        raise ValueError("The executor receipt exceeds 1 MiB.")
    temp = path.with_name(path.name + "." + secrets.token_hex(8))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(data)
            stream.flush()
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.replace(temp, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(fd)
        temp.unlink(missing_ok=True)


def read_json(path: Path, maximum=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise ValueError("The executor receipt is not a bounded regular file.")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("The executor receipt exceeds its bound.")
        return json.loads(data)
    finally:
        os.close(fd)


def identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
            "bytes": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def fingerprint(path: Path, *, owner=0):
    directory(path.parent, owner=owner)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_mode & 0o022 or before.st_nlink != 1:
            raise ValueError("An administrator input is not an immutable owned regular file.")
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        if identity(before) != identity(os.fstat(fd)):
            raise ValueError("An administrator input changed while it was read.")
        return {**identity(before), "digest": "sha256:" + digest.hexdigest()}
    finally:
        os.close(fd)


def open_below(root: Path, relative: str):
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(part in {".", ".."} for part in parts):
        raise ValueError("Select a file below the recorded directory.")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        result = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        info = os.fstat(result)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(result)
            raise ValueError("The result must be one regular file without links.")
        return result
    finally:
        os.close(fd)
