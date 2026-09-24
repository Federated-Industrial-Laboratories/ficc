# SPDX-License-Identifier: Apache-2.0
"""Replace archive journals with bounded scratch files recoverable under the caller's lock."""

import json
import os
import re
import stat
from pathlib import Path


def temporary(name):
    if (name not in {"intent.json", "manifest.json", "controller.json", "archive.pending.json", "retirement.json", "archive.json"}
            and not re.fullmatch(r"[a-f0-9]{64}\.json", name)):
        raise ValueError("The archive journal name is invalid.")
    return ".archive-write-" + name + ".tmp"


def checked(folder, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > maximum):
            raise ValueError("Archive journals must be bounded private regular files without links.")
        return info
    finally:
        os.close(fd)


def open_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(fd)
        raise ValueError("Archive journal directories must be private and owned by this account.")
    return fd


def recover(path, maximum):
    """Discard only this journal's reserved scratch; no effect follows an incomplete write."""
    name = temporary(path.name)
    folder = open_directory(path.parent)
    try:
        try:
            checked(folder, name, maximum)
        except FileNotFoundError:
            return
        os.unlink(name, dir_fd=folder)
        os.fsync(folder)
    finally:
        os.close(folder)


def write(path, value, maximum):
    data = json.dumps(value, allow_nan=False, sort_keys=True).encode()
    write_bytes(path, data, maximum)


def write_bytes(path, data, maximum):
    if len(data) > maximum:
        raise ValueError("The archive journal exceeds its size limit.")
    recover(path, maximum)
    name = temporary(path.name)
    folder = open_directory(path.parent)
    try:
        try:
            checked(folder, path.name, maximum)
        except FileNotFoundError:
            pass
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path.name, src_dir_fd=folder, dst_dir_fd=folder)
        os.fsync(folder)
    finally:
        os.close(folder)


def persist(path, ancestor):
    """Persist every child entry through the existing ancestor before moving source data."""
    path, ancestor = Path(path).absolute(), Path(ancestor).absolute()
    if not path.is_relative_to(ancestor):
        raise ValueError("The archive directory ancestry is invalid.")
    while True:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if os.fstat(fd).st_uid != os.getuid():
                raise ValueError("Archive ancestors must belong to this account.")
            os.fsync(fd)
        finally:
            os.close(fd)
        if path == ancestor:
            break
        path = path.parent
