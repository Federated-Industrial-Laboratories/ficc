# SPDX-License-Identifier: Apache-2.0
"""Copy only bounded private backup members and publish without replacement."""

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from contextlib import contextmanager
from pathlib import Path

from ficc_node.file_access import rename

MAX_DATABASE = 256 * 1024**2
MAX_TOTAL = 512 * 1024**2
MAX_MEMBERS = 8194
MAX_MANIFEST = 2 * 1024**2
HEX32 = r"[a-f0-9]{32}"
MEMBER = re.compile(r"(?:state\.sqlite3|trust/[a-f0-9]{64}|files/" + HEX32 + r"/" + HEX32 + r"\.json)\Z")


def limit(name):
    if not isinstance(name, str) or not MEMBER.fullmatch(name):
        raise ValueError("The backup contains an unsupported member path.")
    return MAX_DATABASE if name == "state.sqlite3" else 262144 if name.startswith("files/") else 16384


def checked(info, directory=False):
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_uid != os.getuid() or info.st_mode & 0o077
            or (not directory and info.st_nlink != 1)):
        raise ValueError("Backup paths must be private, owned directories or regular files without links.")


@contextmanager
def directory(path: Path, private=True):
    path = path.absolute()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if private:
            checked(os.fstat(fd), directory=True)
        yield fd
    finally:
        os.close(fd)


@contextmanager
def member(root, name, create=False):
    # Callers validate complete names before this descriptor-relative walk.
    parts = name.split("/")
    folder = os.dup(root)
    fd = None
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=folder)
                    os.fsync(folder)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
            checked(os.fstat(child), directory=True)
            os.close(folder)
            folder = child
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY
        fd = os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=folder)
        checked(os.fstat(fd))
        yield fd
        if create:
            os.fsync(fd)
            os.fsync(folder)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(folder)


def read(root, name, maximum):
    with member(root, name) as fd:
        if os.fstat(fd).st_size > maximum:
            raise ValueError("A backup member exceeds its size limit.")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("A backup member exceeds its size limit.")
        return data


def write(root, name, data):
    with member(root, name, create=True) as fd, os.fdopen(os.dup(fd), "wb") as stream:
        stream.write(data)
        stream.flush()


def copy(root, target, name):
    maximum = limit(name)
    digest = hashlib.sha256()
    size = 0
    with member(root, name) as source, member(target, name, create=True) as destination:
        initial = os.fstat(source)
        if initial.st_size > maximum:
            raise ValueError("A backup member exceeds its size limit.")
        with os.fdopen(os.dup(source), "rb") as stream, os.fdopen(os.dup(destination), "wb") as output:
            while data := stream.read(262144):
                size += len(data)
                if size > maximum:
                    raise ValueError("A backup member exceeds its size limit.")
                digest.update(data)
                output.write(data)
            output.flush()
        final = os.fstat(source)
        if (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (
                final.st_size, final.st_mtime_ns, final.st_ctime_ns) or size != initial.st_size:
            raise ValueError("A backup member changed while it was read.")
    return {"size": size, "sha256": digest.hexdigest()}


def inventory(root, bundle=False, maintenance=False):
    found = []
    count = 0

    def walk(fd, prefix=""):
        nonlocal count
        with os.scandir(fd) as entries:
            for entry in entries:
                count += 1
                if count > MAX_MEMBERS + 32:
                    raise ValueError("The backup member count exceeds the limit.")
                name = prefix + entry.name
                info = entry.stat(follow_symlinks=False)
                folders = (name in {"trust", "files", "downloads"}
                           or (not bundle and name == "cli-requests") or re.fullmatch("files/" + HEX32, name))
                if folders:
                    checked(info, directory=True)
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        walk(child, name + "/")
                    finally:
                        os.close(child)
                elif not bundle and name in {"service.lock", "state.sqlite3-wal", "state.sqlite3-shm"}:
                    checked(info)
                    if info.st_size > MAX_DATABASE:
                        raise ValueError("The state journal exceeds the backup size limit.")
                elif not bundle and maintenance and name == "archive.pending.json":
                    checked(info)
                    if info.st_size > 1024 * 1024:
                        raise ValueError("The maintenance intent exceeds its size limit.")
                elif not bundle and name == "control.sock":
                    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                        raise ValueError("The old control socket is not private.")
                elif not bundle and re.fullmatch("files/" + HEX32 + "/namespace.lock", name):
                    checked(info)
                elif not bundle and re.fullmatch(r"cli-requests/(?:requests\.lock|[a-f0-9]{64}\.json)", name):
                    checked(info)
                    if info.st_size > 65536:
                        raise ValueError("A CLI receipt exceeds its size limit.")
                elif bundle and name == "manifest.json":
                    checked(info)
                    if info.st_size > MAX_MANIFEST:
                        raise ValueError("The backup manifest exceeds the size limit.")
                else:
                    maximum = limit(name)
                    checked(info)
                    if info.st_size > maximum:
                        raise ValueError("A backup member exceeds its size limit.")
                    found.append(name)
    walk(root)
    if "state.sqlite3" not in found or len(found) > MAX_MEMBERS:
        raise ValueError("The backup member set is incomplete or too large.")
    return sorted(found)


def encode(value):
    return json.dumps(value, sort_keys=True, allow_nan=False, indent=2).encode() + b"\n"


@contextmanager
def staging(destination: Path):
    destination = destination.absolute()
    with directory(destination.parent, private=False) as parent:
        try:
            os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("The destination must be a new directory.")
        name = ".ficc-maintenance-" + secrets.token_hex(16)
        os.mkdir(name, 0o700, dir_fd=parent)
        fd = None
        published = False
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            yield fd, Path(f"/proc/self/fd/{fd}")
            os.fsync(fd)
            rename(parent, os.fsencode(name), parent, os.fsencode(destination.name))
            try:
                os.fsync(parent)
            except BaseException:
                rename(parent, os.fsencode(destination.name), parent, os.fsencode(name))
                raise
            published = True
        finally:
            if fd is not None:
                os.close(fd)
            if not published:
                if fd is None:
                    os.rmdir(name, dir_fd=parent)
                else:
                    shutil.rmtree(name, dir_fd=parent)
