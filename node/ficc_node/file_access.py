# SPDX-License-Identifier: Apache-2.0
"""Acquire registered Linux objects without following links or crossing mounts."""

import base64
import ctypes
import errno
import hashlib
import os
import platform
import stat
from contextlib import contextmanager

CHUNK = 262144
MAX_FILE = 16 * 1024**3
RESERVED = b".ficc-"
LIBC = ctypes.CDLL(None, use_errno=True)


class FileError(ValueError):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


class How(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64),
                ("resolve", ctypes.c_uint64)]


def opened(parent, path, flags, beneath=True):
    if platform.machine() not in {"x86_64", "aarch64"}:
        raise FileError("files_unavailable", "This architecture does not support the file adapter.")
    how = How(flags | os.O_CLOEXEC | os.O_NOFOLLOW, 0, 0x04 | 0x02 | (0x08 | 0x01 if beneath else 0))
    fd = LIBC.syscall(ctypes.c_long(437), ctypes.c_int(parent), ctypes.c_char_p(path),
                      ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        error = ctypes.get_errno()
        if error in (errno.ENOSYS, errno.EINVAL):
            raise FileError("files_unavailable", "The kernel does not support safe file lookup.")
        raise OSError(error, os.strerror(error))
    return fd


def rename(source_fd, source, destination_fd, destination, flags=1):
    result = LIBC.renameat2(ctypes.c_int(source_fd), ctypes.c_char_p(source),
                            ctypes.c_int(destination_fd), ctypes.c_char_p(destination), ctypes.c_uint(flags))
    if result:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def identity(info):
    return {"dev": info.st_dev, "ino": info.st_ino, "type": stat.S_IFMT(info.st_mode),
            "size": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def same(current, expected, directory=False):
    fields = ("dev", "ino", "type") if directory else ("dev", "ino", "type", "size", "mtime_ns", "ctime_ns")
    return all(current.get(key) == expected.get(key) for key in fields)


def encode(name):
    return base64.urlsafe_b64encode(name).decode("ascii")


def decode(name):
    if not isinstance(name, str) or len(name) > 340:
        raise FileError("invalid_entry", "The entry name is invalid.")
    try:
        value = base64.b64decode(name, altchars=b"-_", validate=True)
    except ValueError:
        raise FileError("invalid_entry", "The entry name is invalid.") from None
    if not value or len(value) > 255 or value in (b".", b"..") or b"/" in value or b"\0" in value:
        raise FileError("invalid_entry", "The entry name is invalid.")
    return value


def new_name(value):
    if not isinstance(value, str):
        raise FileError("invalid_name", "Enter a file name.")
    raw = value.encode("utf-8")
    decode(encode(raw))
    if raw.startswith(RESERVED):
        raise FileError("invalid_name", "This name is reserved for transfer state.")
    return raw


def transfer_name(value):
    raw = decode(value["name_b64"]) if value.get("name_b64") else new_name(value["name"])
    if raw.startswith(RESERVED):
        raise FileError("invalid_name", "This name is reserved for transfer state.")
    return raw


def parts(reference):
    values = reference.get("parts")
    if not isinstance(values, list) or len(values) > 64:
        raise FileError("invalid_entry", "The entry reference is invalid.")
    result = [decode(value) for value in values]
    if any(value.startswith(RESERVED) for value in result) or sum(map(len, result)) + len(result) > 4096:
        raise FileError("invalid_entry", "The entry path is invalid.")
    return result


@contextmanager
def root_fd(root):
    path = root.get("path")
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise FileError("invalid_root", "The registered root is invalid.")
    fd = opened(-100, os.fsencode(path), os.O_RDONLY | os.O_DIRECTORY, False)
    try:
        if root.get("identity") and not same(identity(os.fstat(fd)), root["identity"], True):
            raise FileError("root_changed", "The registered directory was replaced.")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def entry_fd(root, reference, flags=os.O_RDONLY):
    path = b"/".join(parts(reference)) or b"."
    with root_fd(root) as parent:
        fd = opened(parent, path, flags | (0 if flags & os.O_PATH else os.O_NONBLOCK))
        try:
            current = identity(os.fstat(fd))
            if not same(current, reference["identity"], current["type"] == stat.S_IFDIR):
                raise FileError("stale_entry", "The selected entry changed. Refresh the directory.")
            yield fd
        finally:
            os.close(fd)


@contextmanager
def parent_fd(root, reference):
    values = parts(reference)
    if not values:
        raise FileError("root_action", "The registered root cannot be changed.")
    with root_fd(root) as root_handle:
        fd = opened(root_handle, b"/".join(values[:-1]) or b".", os.O_RDONLY | os.O_DIRECTORY)
        try:
            if not same(identity(os.fstat(fd)), reference["parent"], True):
                raise FileError("stale_entry", "The parent directory changed.")
            yield fd, values[-1]
        finally:
            os.close(fd)


def checked_at(parent, name, expected):
    current = identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
    if not same(current, expected):
        raise FileError("stale_entry", "The selected entry changed. Refresh the directory.")
    return current


def reference(fd, values, parent=None):
    result = {"parts": [encode(value) for value in values], "identity": identity(os.fstat(fd))}
    if parent is not None:
        result["parent"] = identity(os.fstat(parent))
    return result


def display(value):
    result = []
    for char in value.decode("utf-8", "surrogateescape"):
        code = ord(char)
        if 0xDC80 <= code <= 0xDCFF:
            result.append(f"\\x{code - 0xDC00:02x}")
        elif char == "\\" or code < 32 or code == 127:
            result.append(char.encode("unicode_escape").decode("ascii"))
        else:
            result.append(char)
    return "".join(result)


def regular(info):
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
        raise FileError("unsupported_file", "Select a regular file no larger than 16 GiB.")


def change_mode(fd, mode):
    if LIBC.syscall(ctypes.c_long(452), ctypes.c_int(fd), ctypes.c_char_p(b""),
                    ctypes.c_uint(mode), ctypes.c_int(0x1000)):
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EINVAL}:
            raise FileError("mode_unavailable", "The kernel does not support descriptor mode changes.")
        raise OSError(error, os.strerror(error))


def mode_supported():
    LIBC.syscall(ctypes.c_long(452), ctypes.c_int(-1), ctypes.c_char_p(b""), ctypes.c_uint(0), ctypes.c_int(0x1000))
    return ctypes.get_errno() == errno.EBADF


def sync_filesystem(fd):
    if LIBC.syncfs(ctypes.c_int(fd)):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise FileError("interrupted", "File verification was interrupted.")


def file_hash(fd, expected=None, cancel=None):
    import time
    before = identity(os.fstat(fd))
    regular(os.fstat(fd))
    if expected and not same(before, expected):
        raise FileError("source_changed", "The source file changed.")
    value, offset, deadline = hashlib.sha256(), 0, time.monotonic() + 300
    while offset < before["size"]:
        check_cancel(cancel)
        if time.monotonic() > deadline:
            raise FileError("verification_timeout", "File verification exceeded its deadline.")
        data = os.pread(fd, min(CHUNK, before["size"] - offset), offset)
        if not data:
            break
        value.update(data)
        offset += len(data)
    if not same(before, identity(os.fstat(fd))) or offset != before["size"]:
        raise FileError("source_changed", "The source file changed during verification.")
    return value.hexdigest()
