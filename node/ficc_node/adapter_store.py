# SPDX-License-Identifier: Apache-2.0
"""Keep private provider bindings, immutable packages and durable request records."""

import fcntl
import hashlib
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from ficc.errors import Failure
from ficc.modules.manifest import package_path, validate_manifest
from ficc.modules.validation import digest, dumps, fields, loads


def root():
    path = Path.home()
    for part in (".local", "state", "ficc", "adapters"):
        path /= part
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise Failure("adapter_storage_invalid", "Provider state ancestors must be owned and must not permit other accounts to write.")
    if path.stat().st_mode & 0o077:
        raise Failure("adapter_storage_invalid", "Provider state must have mode 0700.")
    return path


def read(path, maximum=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > maximum):
            raise Failure("adapter_storage_invalid", "Provider state must contain private, bounded regular files.")
        value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise Failure("adapter_storage_invalid", "Provider state exceeds its size limit.")
        return value


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(path, value):
    if path.exists() or path.is_symlink():
        read(path)
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(dumps(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def locked():
    base = root()
    fd = os.open(base / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise Failure("adapter_storage_invalid", "The provider lock is not private.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Failure("adapter_busy", "Another provider request is active.") from exc
        yield base
    finally:
        os.close(fd)


def directory(base, name):
    path = base / name
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Failure("adapter_storage_invalid", "Provider directories must be private and owned by this account.")
    return path


def verify(base, checksum):
    path = directory(base, "packages") / digest(checksum)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Failure("adapter_package_invalid", "The provider package directory is invalid.")
    manifest = validate_manifest(loads(read(path / "manifest.json")))
    actual = {str(item.relative_to(path)) for item in path.rglob("*") if not item.is_dir()}
    if actual != set(manifest["files"]) | {"manifest.json"}:
        raise Failure("adapter_package_invalid", "The provider package file inventory changed.")
    for name, expected in manifest["files"].items():
        target = path / name
        if target.resolve() != target.absolute() or hashlib.sha256(read(target, 16 * 1024 * 1024)).hexdigest() != expected:
            raise Failure("adapter_package_invalid", "The provider package content changed.")
    if manifest.get("role") != "provider-adapter" or manifest["adapter"]["execution"] != "enrolled-node":
        raise Failure("adapter_package_invalid", "This package cannot execute on an enrolled node.")
    return path, manifest


def install(base, parameters, stream):
    fields(parameters, {"digest", "manifest", "members"})
    checksum, manifest = digest(parameters["digest"]), validate_manifest(parameters["manifest"])
    members = parameters["members"]
    if not isinstance(members, list) or len(members) != len(manifest["files"]):
        raise Failure("adapter_package_invalid", "The provider transfer inventory is incomplete.")
    names, total = set(), 0
    for item in members:
        fields(item, {"path", "size", "sha256"})
        name = package_path(item["path"])
        if (name in names or manifest["files"].get(name) != item["sha256"]
                or type(item["size"]) is not int or not 0 <= item["size"] <= 16 * 1024 * 1024):
            raise Failure("adapter_package_invalid", "A provider transfer member is invalid.")
        names.add(name)
        total += item["size"]
    if total > 64 * 1024 * 1024:
        raise Failure("adapter_package_invalid", "The provider transfer exceeds its size limit.")
    packages = directory(base, "packages")
    target = packages / checksum
    existing = target.exists()
    if not existing and (len(list(packages.iterdir())) >= 64 or
            sum(item.stat().st_size for item in packages.rglob("*") if item.is_file()) + total > 128 * 1024 * 1024):
        raise Failure("adapter_package_capacity", "The node provider package storage is full.")
    temporary = Path(tempfile.mkdtemp(prefix=".install-", dir=packages))
    try:
        for item in members:
            value = stream.read(item["size"])
            if len(value) != item["size"] or hashlib.sha256(value).hexdigest() != item["sha256"]:
                raise Failure("adapter_package_invalid", "The provider transfer content does not match its checksum.")
            path = temporary / item["path"]
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open("xb") as output:
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
            path.chmod(0o500 if item["path"] == manifest["runtime"]["entry"] and manifest["runtime"]["kind"] == "native" else 0o400)
        if stream.read(1):
            raise Failure("adapter_package_invalid", "The provider transfer has extra bytes.")
        write(temporary / "manifest.json", manifest)
        (temporary / "manifest.json").chmod(0o400)
        for path in sorted((item for item in temporary.rglob("*") if item.is_dir()), reverse=True):
            sync(path)
            path.chmod(0o500)
        sync(temporary)
        if not existing:
            temporary.chmod(0o500)
            os.rename(temporary, target)
            sync(packages)
        verify(base, checksum)
        return {"installed": True}
    finally:
        if temporary.exists():
            for path in [temporary, *temporary.rglob("*")]:
                if path.is_dir():
                    path.chmod(0o700)
            shutil.rmtree(temporary)
