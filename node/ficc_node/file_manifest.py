# SPDX-License-Identifier: Apache-2.0
"""Bind a whole source with a fixed-size digest and reserve physical file blocks."""

import ctypes
import errno
import hashlib
import os
import re

from .file_access import CHUNK, LIBC, FileError


def manifest(value):
    if (not isinstance(value, dict) or set(value) != {"algorithm", "digest"}
            or value["algorithm"] not in {"sha256", "sha256-chain-v1"}
            or not isinstance(value["digest"], str) or not re.fullmatch("[a-f0-9]{64}", value["digest"])):
        raise FileError("invalid_manifest", "Supply a supported source digest manifest.")
    return value


def chain_seed(size):
    return hashlib.sha256(f"ficc-upload-v1:{size}:{CHUNK}".encode("ascii")).digest()


def chain_next(previous, chunk_digest):
    return hashlib.sha256(previous + chunk_digest).digest()


def journal_bytes(size):
    return ((size + CHUNK - 1) // CHUNK) * 32


def reserve(fd, size):
    """Use KEEP_SIZE so allocation survives interruption without faking received bytes."""
    if not size:
        return
    if LIBC.fallocate(ctypes.c_int(fd), ctypes.c_int(1), ctypes.c_longlong(0), ctypes.c_longlong(size)):
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
            raise FileError("reservation_unavailable", "The destination cannot reserve file blocks safely.")
        if error in {errno.ENOSPC, errno.EDQUOT, errno.EFBIG}:
            raise FileError("disk_capacity", "The destination cannot reserve the requested capacity.")
        raise OSError(error, os.strerror(error))
