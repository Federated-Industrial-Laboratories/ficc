# SPDX-License-Identifier: Apache-2.0
"""Inspect bounded module archives and publish verified, read-only package files."""

import hashlib
import io
import os
import re
import shutil
import stat
import struct
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .manifest import package_path, validate_manifest
from .validation import digest as valid_digest
from .validation import invalid, loads

MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_MANIFEST = 64 * 1024
MAX_MEMBERS = 256
INSPECTION_SECONDS = 5


@dataclass(frozen=True)
class Inspection:
    """Retain the inspected archive; callers receive copies of public metadata."""

    digest: str
    _archive: bytes
    _manifest: bytes
    expanded_bytes: int

    @property
    def manifest(self) -> dict:
        return loads(self._manifest, MAX_MANIFEST)

    def public(self) -> dict:
        return {"digest": self.digest, "manifest": self.manifest, "publisher_verified": False,
                "compressed_bytes": len(self._archive), "expanded_bytes": self.expanded_bytes}


def _directory(data: bytes) -> None:
    # Reject large central directories before ZipFile allocates one object per entry.
    offset = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if offset < 0 or len(data) - offset < 22 or not data.startswith(b"PK\x03\x04"):
        raise invalid("The module archive is not a supported ZIP file.")
    _, disk, directory_disk, count_disk, count, size, start, comment = struct.unpack_from(
        "<4s4H2IH", data, offset)
    if (disk or directory_disk or count != count_disk or not 1 <= count <= MAX_MEMBERS
            or start + size != offset or offset + 22 + comment != len(data)):
        raise invalid("The module ZIP directory is invalid or exceeds the limit.")


def inspect_archive(data: bytes) -> Inspection:
    """Validate all bytes and file digests without extracting or executing the archive."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_ARCHIVE:
        raise invalid("The module archive must be at most 16 MiB.")
    _directory(data)
    deadline = time.monotonic() + INSPECTION_SECONDS
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if not 1 <= len(members) <= MAX_MEMBERS:
                raise invalid("The module archive member count exceeds the limit.")
            names, sizes, folded = set(), 0, set()
            for member in members:
                name = package_path(member.filename)
                mode = member.external_attr >> 16
                if (member.orig_filename != member.filename or name.casefold() in folded
                        or member.is_dir() or member.external_attr & 0x10
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or mode & 0o7000
                        or member.flag_bits & 1 or member.extract_version > 20
                        or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                    raise invalid("The module archive contains an unsupported or repeated member.")
                if not 0 <= member.file_size <= MAX_FILE:
                    raise invalid("A module file exceeds the size limit.")
                names.add(name)
                folded.add(name.casefold())
                sizes += member.file_size
            if sizes > MAX_EXPANDED or "manifest.json" not in names:
                raise invalid("The module expanded size or manifest is invalid.")
            for name in names:
                parts = name.split("/")
                if any("/".join(parts[:i]).casefold() in folded for i in range(1, len(parts))):
                    raise invalid("A module file conflicts with a directory path.")
            manifest_data = _read(archive, "manifest.json", MAX_MANIFEST, deadline)
            manifest = validate_manifest(loads(manifest_data, MAX_MANIFEST))
            if names != {"manifest.json", *manifest["files"]}:
                raise invalid("The archive members do not match the complete file inventory.")
            for name, expected in manifest["files"].items():
                content = _read(archive, name, MAX_FILE, deadline)
                if hashlib.sha256(content).hexdigest() != expected:
                    raise invalid("A module file digest does not match its inventory.")
    except (zipfile.BadZipFile, EOFError, RuntimeError, NotImplementedError, OSError) as exc:
        raise invalid("The module archive could not be read safely.") from exc
    return Inspection(hashlib.sha256(data).hexdigest(), data, manifest_data, sizes)


def _read(archive: zipfile.ZipFile, name: str, maximum: int, deadline: float) -> bytes:
    result = bytearray()
    with archive.open(name) as source:
        while True:
            if time.monotonic() > deadline:
                raise invalid("The module inspection exceeded its time limit.")
            chunk = source.read(min(65536, maximum + 1 - len(result)))
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > maximum:
                raise invalid("A module file exceeds the size limit.")


def _sync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def recover_stages(root: Path) -> None:
    """Remove unpublished stages while the caller owns the stopped or starting controller."""
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    remaining = 64 * MAX_MEMBERS * 121
    deadline = time.monotonic() + INSPECTION_SECONDS

    def discard(parent: int, name: str, depth: int = 0) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 120 or time.monotonic() > deadline:
            raise invalid("Module staging cleanup exceeded its limit. Restart to continue cleanup.")
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if info.st_uid != os.getuid():
            raise invalid("A module staging member has an invalid owner.")
        if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_FILE:
            os.unlink(name, dir_fd=parent)
            return
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise invalid("A module staging member is not a private regular file or directory.")
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise invalid("The module staging directory changed during cleanup.")
            os.fchmod(fd, 0o700)
            with os.scandir(fd) as entries:
                for entry in entries:
                    discard(fd, entry.name, depth + 1)
        finally:
            os.close(fd)
        os.rmdir(name, dir_fd=parent)

    try:
        info = os.fstat(root_fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise invalid("The module storage directory is not private.")
        with os.scandir(root_fd) as entries:
            for index, entry in enumerate(entries):
                if index >= 128:
                    raise invalid("The module storage entry count exceeds its limit.")
                if re.fullmatch(r"\.stage-[a-z0-9_]{8}", entry.name):
                    discard(root_fd, entry.name)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def publish(root: Path, inspection: Inspection) -> Path:
    """Publish only the validated archive snapshot; an existing package is verified."""
    checked = inspect_archive(inspection._archive)
    if checked.digest != inspection.digest or checked._manifest != inspection._manifest:
        raise invalid("The inspected package identity changed.")
    destination = root / checked.digest
    if destination.exists() or destination.is_symlink():
        verify(destination, checked.manifest, checked._manifest)
        return destination
    stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=root))
    try:
        with zipfile.ZipFile(io.BytesIO(checked._archive)) as archive:
            for name in ["manifest.json", *checked.manifest["files"]]:
                target = stage / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                content = _read(archive, name, MAX_FILE, time.monotonic() + INSPECTION_SECONDS)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    executable = (checked.manifest["runtime"].get("entry") == name
                                  and checked.manifest["runtime"]["kind"] == "native")
                    os.fchmod(stream.fileno(), 0o500 if executable else 0o400)
                    os.fsync(stream.fileno())
        for directory, _, _ in os.walk(stage, topdown=False):
            os.chmod(directory, 0o500)
            _sync(Path(directory))
        os.rename(stage, destination)
        _sync(root)
    except BaseException:
        if stage.exists():
            for directory, _, _ in os.walk(stage):
                os.chmod(directory, 0o700)
            shutil.rmtree(stage)
        raise
    return destination


def verify(path: Path, manifest: dict, manifest_bytes: bytes) -> None:
    """Refuse modified, linked or additional package content before use."""
    valid_digest(path.name)
    if path.is_symlink() or not path.is_dir():
        raise invalid("The installed module directory is invalid.")
    found = set()
    expected = {"manifest.json": hashlib.sha256(manifest_bytes).hexdigest(), **manifest["files"]}
    expected_dirs = {str(parent) for name in expected for parent in Path(name).parents}
    total = 0
    for directory, directories, files in os.walk(path, followlinks=False):
        info = Path(directory).lstat()
        if (Path(directory).relative_to(path).as_posix() not in expected_dirs
                or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o500
                or info.st_uid != os.getuid()
                or any((Path(directory) / name).is_symlink() for name in directories)):
            raise invalid("An installed module directory has invalid content or permissions.")
        for name in files:
            target = Path(directory) / name
            relative = target.relative_to(path).as_posix()
            if relative not in expected:
                raise invalid("The installed module contains an unexpected file.")
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                executable = (manifest["runtime"]["kind"] == "native"
                              and manifest["runtime"]["entry"] == relative)
                if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE
                        or info.st_nlink != 1 or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != (0o500 if executable else 0o400)):
                    raise invalid("The installed module file is invalid.")
                checksum = hashlib.sha256()
                size = 0
                while chunk := os.read(fd, 65536):
                    size += len(chunk)
                    total += len(chunk)
                    if size > MAX_FILE or total > MAX_EXPANDED:
                        raise invalid("The installed module exceeds the size limit.")
                    checksum.update(chunk)
                if checksum.hexdigest() != expected[relative]:
                    raise invalid("The installed module digest changed.")
            finally:
                os.close(fd)
            found.add(relative)
    if found != expected.keys():
        raise invalid("The installed module is incomplete.")
