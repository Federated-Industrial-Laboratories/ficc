# SPDX-License-Identifier: Apache-2.0
"""Bind a private Unix display to its inode and kernel-authenticated process."""

import os
import re
import socket
import stat
from contextlib import contextmanager

from ficc.errors import Failure
from ficc.modules.adapter_protocol import integer
from ficc.modules.validation import fields, text
from ficc.modules.watcher import identity

from .adapter_binding import path, peer_record


def descriptor(value):
    fields(value, {"socket_path", "device", "inode", "uid", "pid", "start"})
    path(value["socket_path"])
    integer(value["pid"], 1, 2**31 - 1)
    integer(value["uid"], 0, 2**32 - 1)
    integer(value["device"], 0, 2**53 - 1)
    integer(value["inode"], 1, 2**53 - 1)
    if re.fullmatch(r"[0-9]{1,24}", text(value["start"], 24)) is None:
        raise Failure("adapter_console_invalid", "The display process identity is invalid.")
    return value


def metadata(location):
    if location.resolve() != location:
        raise Failure("adapter_console_invalid", "The display socket path contains a link.")
    info = location.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Failure("adapter_console_denied", "The display socket must be private and owned.")
    return info


@contextmanager
def opened(parameters):
    fields(parameters, {"pid", "socket_path"})
    pid = integer(parameters["pid"], 1, 2**31 - 1)
    location = path(parameters["socket_path"])
    original = metadata(location)
    fd = os.open(location, os.O_PATH | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) != (original.st_dev, original.st_ino):
            raise Failure("adapter_console_changed", "The display socket changed during attachment.")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(2)
            stream.connect(f"/proc/{os.getpid()}/fd/{fd}")
            value = {"socket_path": str(location), **peer_record(stream, info)}
            if value["pid"] != pid:
                raise Failure("adapter_console_changed", "The display peer differs from the selected process.")
            check(value)
            yield stream, descriptor(value)
    finally:
        os.close(fd)


def describe(parameters):
    with opened(parameters) as (_, value):
        return value


def check(value):
    descriptor(value)
    info = metadata(path(value["socket_path"]))
    if ((info.st_dev, info.st_ino, info.st_uid) != (value["device"], value["inode"], value["uid"])
            or identity(value["pid"]) != value["start"]):
        raise Failure("adapter_console_changed", "The display process or socket changed.")


@contextmanager
def connect(value):
    check(value)
    with opened({key: value[key] for key in ("pid", "socket_path")}) as (stream, current):
        if current != value:
            raise Failure("adapter_console_changed", "The display peer identity changed after selection.")
        yield stream
