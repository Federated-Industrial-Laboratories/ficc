# SPDX-License-Identifier: Apache-2.0
"""Validate private directories and copy the exact trusted evaluator bytes."""

import hashlib
import os
import re
import stat
from pathlib import Path

MAX_SOURCE = 16 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024


def safe_file(value: os.stat_result) -> bool:
    return (stat.S_ISREG(value.st_mode) and value.st_uid in (0, os.getuid())
            and not value.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID))


def directories(source: Path, run: Path) -> tuple[Path, Path]:
    source, run = Path(source).absolute(), Path(run).absolute()
    for path in (source, run):
        value = path.lstat()
        if (path != path.resolve() or not stat.S_ISDIR(value.st_mode)
                or value.st_uid != os.getuid() or value.st_mode & 0o022):
            raise ValueError("The policy directory is unsafe.")
    if (run.stat().st_mode & 0o777 != 0o700 or any(run.iterdir())
            or source == run or source in run.parents or run in source.parents):
        raise ValueError("The policy run directory must be private and empty.")
    total, files, policies = 0, 0, 0
    for path in source.rglob("*"):
        value = path.lstat()
        if len(path.relative_to(source).parts) > 8:
            raise ValueError("The policy source exceeds its path limit.")
        if stat.S_ISDIR(value.st_mode):
            if value.st_uid != os.getuid() or value.st_mode & 0o022:
                raise ValueError("The policy directory is unsafe.")
            continue
        if not safe_file(value) or (path.suffix != ".rego" and path.name != "data.json"):
            raise ValueError("The policy source contains an unsupported file.")
        total += value.st_size
        files += 1
        policies += int(path.suffix == ".rego")
        if total > MAX_SOURCE or files > 256:
            raise ValueError("The policy source exceeds its size limit.")
    if not policies:
        raise ValueError("The policy source has no Rego files.")
    return source, run


def binary(configuration: dict, target: Path) -> None:
    if not isinstance(configuration, dict) or set(configuration) != {"binary", "sha256"}:
        raise ValueError("The policy provider configuration is invalid.")
    name, expected = configuration["binary"], configuration["sha256"]
    if (not isinstance(name, str) or not Path(name).is_absolute()
            or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected)):
        raise ValueError("The policy binary identity is invalid.")
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not safe_file(before) or not before.st_mode & 0o111 or before.st_size > MAX_BINARY:
            raise ValueError("The policy binary is unsafe.")
        digest, size = hashlib.sha256(), 0
        with target.open("xb") as destination:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_BINARY:
                    raise ValueError("The policy binary exceeds its size limit.")
                digest.update(chunk)
                destination.write(chunk)
        after = os.fstat(source.fileno())
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (size != before.st_size or any(getattr(before, key) != getattr(after, key) for key in identity)
                or digest.hexdigest() != expected.lower()):
            raise ValueError("The policy binary digest does not match.")
    target.chmod(0o500)
