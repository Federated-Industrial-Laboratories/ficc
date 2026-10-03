# SPDX-License-Identifier: Apache-2.0
"""Read private secret files and atomically publish synced owner-only records."""

import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

from .secret_sdk import SecretError


def checked(info, directory=False):
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_uid != os.getuid() or info.st_mode & 0o077
            or (not directory and info.st_nlink != 1)):
        raise SecretError()


@contextmanager
def directory(path):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(path).absolute().parts[1:]:
            if part in {".", ".."}:
                raise SecretError()
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        checked(os.fstat(fd), True)
        yield fd
    finally:
        os.close(fd)


def read(folder, name, maximum=65536):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
    try:
        checked(os.fstat(fd))
        with os.fdopen(os.dup(fd), "rb") as stream:
            value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise SecretError()
        return value
    finally:
        os.close(fd)


def private_file(path, maximum=65536):
    path = Path(path).absolute()
    with directory(path.parent) as folder:
        return read(folder, path.name, maximum)


def publish(folder, name, value, *, replace=False):
    temporary = ".pending-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, name, src_dir_fd=folder, dst_dir_fd=folder)
        else:
            os.link(temporary, name, src_dir_fd=folder, dst_dir_fd=folder, follow_symlinks=False)
            os.unlink(temporary, dir_fd=folder)
        os.fsync(folder)
    finally:
        try:
            os.unlink(temporary, dir_fd=folder)
        except FileNotFoundError:
            pass
