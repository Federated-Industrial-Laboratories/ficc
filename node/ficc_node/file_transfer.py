# SPDX-License-Identifier: Apache-2.0
"""Keep resumable chunks and commit verified files on their destination filesystem."""

import hashlib
import os
import stat
import time
from contextlib import contextmanager

from .file_access import (
    CHUNK,
    MAX_FILE,
    FileError,
    check_cancel,
    checked_at,
    entry_fd,
    file_hash,
    identity,
    opened,
    regular,
    rename,
    same,
    transfer_name,
)
from .file_state import load, locked, save
from .job_state import digest, read

TERMINAL = {"succeeded", "cancelled"}


@contextmanager
def stage(root, record):
    with entry_fd(root, record["parent"], os.O_RDONLY | os.O_DIRECTORY) as parent:
        fd = opened(parent, record["stage"].encode(), os.O_RDONLY | os.O_DIRECTORY)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise FileError("invalid_partial", "The partial directory is not private.")
            yield parent, fd
        finally:
            os.close(fd)


def summary(record):
    return {key: record.get(key) for key in ("id", "state", "size", "offset", "sha256", "prefix_sha256", "cleanup_pending")}


def prepare(root, record, base):
    if record.get("prepared", record["state"] != "preparing") or record["state"] in TERMINAL | {"discarding"}:
        return record
    with entry_fd(root, record["parent"], os.O_RDONLY | os.O_DIRECTORY) as parent:
        try:
            os.mkdir(record["stage"].encode(), mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
        os.fsync(parent)
    with stage(root, record) as (_, folder):
        for name in (b"data", b"chunks"):
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder)
            except FileExistsError:
                fd = opened(folder, name, os.O_RDWR | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                regular(info)
                if info.st_size or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise FileError("invalid_partial", "The unprepared partial file changed.")
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(folder)
    record.update(state="running", prepared=True)
    save(base, record)
    return record


def discard(root, record, base):
    record["state"] = "discarding"
    save(base, record)
    try:
        with stage(root, record) as (parent, folder):
            for name in (b"data", b"chunks"):
                try:
                    info = os.stat(name, dir_fd=folder, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                regular(info)
                if info.st_uid != os.getuid() or info.st_nlink != 1:
                    raise FileError("invalid_partial", "The retained partial file changed.")
                os.unlink(name, dir_fd=folder)
            os.fsync(folder)
            os.rmdir(record["stage"].encode(), dir_fd=parent)
            os.fsync(parent)
    except FileNotFoundError:
        pass
    record["state"] = "cancelled"
    save(base, record)


def begin(request, base):
    spec = request["spec"]
    size = spec["size"]
    if type(size) is not int or not 0 <= size <= MAX_FILE:
        raise FileError("file_limit", "The file exceeds 16 GiB.")
    signature = digest({"root": request["root"], "spec": spec})
    previous = load(base, request["transfer_id"])
    if previous:
        if previous["digest"] != signature:
            raise FileError("idempotency_conflict", "The transfer identity is already in use.")
        return prepare(request["root"], previous, base) if request.get("prepare", True) else previous
    count, reserved = 0, 0
    for path in base.glob("*.json"):
        item = read(path, 262144)
        if item.get("kind") == "transfer" and (item["state"] not in TERMINAL or item.get("cleanup_pending") or (
                item.get("export") and item["state"] == "succeeded")):
            count += 1
            reserved += item["size"] + (item.get("expected") or {}).get("size", 0)
    if count >= 64 or reserved + size + (spec.get("expected") or {}).get("size", 0) > 64 * 1024**3:
        raise FileError("capacity", "The retained partial-file quota is full.")
    root = request["root"]
    if root.get("read_only"):
        raise FileError("read_only", "This root is read-only.")
    with entry_fd(root, spec["parent"], os.O_RDONLY | os.O_DIRECTORY) as parent:
        available = os.fstatvfs(parent)
        if available.f_bavail * available.f_frsize < size + 256 * 1024**2:
            raise FileError("disk_capacity", "The destination lacks reserved free space.")
        name = transfer_name(spec)
        try:
            destination = identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
        except FileNotFoundError:
            destination = None
        if destination != spec.get("expected") or (destination and destination["type"] != stat.S_IFREG):
            raise FileError("destination_changed", "The destination changed. Create a new preview.")
        record = {"id": request["transfer_id"], "kind": "transfer", "digest": signature,
                  "root_id": root["id"], "parent": spec["parent"], "name": spec["name"], "name_b64": spec.get("name_b64"),
                  "export": root.get("export", False), "cleanup_pending": False, "prepared": False,
                  "expected": destination, "size": size, "offset": 0, "sha256": None,
                  "state": "preparing", "stage": ".ficc-transfer-" + request["transfer_id"]}
        save(base, record)
    return prepare(root, record, base) if request.get("prepare", True) else record


def write_chunk(request, data, record, base):
    offset = request["offset"]
    if type(offset) is not int or offset < 0 or offset % CHUNK or offset > record["offset"]:
        raise FileError("invalid_offset", "The chunk offset is invalid.")
    if len(data) != min(CHUNK, record["size"] - offset) or not data:
        raise FileError("invalid_chunk", "The chunk length is invalid.")
    hashed = hashlib.sha256(data).digest()
    if hashed.hex() != request.get("sha256"):
        raise FileError("digest_mismatch", "The chunk digest does not match.")
    if record["state"] != "running":
        raise FileError("transfer_state", "This transfer does not accept chunks.")
    with stage(request["root"], record) as (_, folder):
        fd = opened(folder, b"data", os.O_RDWR)
        journal = opened(folder, b"chunks", os.O_RDWR)
        try:
            if offset < record["offset"]:
                if os.pread(fd, len(data), offset) != data or os.pread(journal, 32, offset // CHUNK * 32) != hashed:
                    raise FileError("source_changed", "The selected source does not match the accepted prefix.")
                return record
            os.ftruncate(fd, offset)
            os.ftruncate(journal, offset // CHUNK * 32)
            written = 0
            while written < len(data):
                written += os.pwrite(fd, data[written:], offset + written)
            os.fsync(fd)
            if os.pwrite(journal, hashed, offset // CHUNK * 32) != 32:
                raise OSError("Incomplete chunk journal write.")
            os.fsync(journal)
        finally:
            os.close(fd)
            os.close(journal)
    record["offset"] += len(data)
    save(base, record)
    return record


def verify_prefix(root, record, cancel=None):
    deadline = time.monotonic() + 300
    check_cancel(cancel)
    with stage(root, record) as (_, folder):
        fd = opened(folder, b"data", os.O_RDWR)
        journal = opened(folder, b"chunks", os.O_RDWR)
        try:
            expected = record["offset"]
            hashed = hashlib.sha256()
            for offset in range(0, expected, CHUNK):
                check_cancel(cancel)
                if time.monotonic() > deadline:
                    raise FileError("verification_timeout", "Partial verification exceeded its deadline.")
                data = os.pread(fd, min(CHUNK, expected-offset), offset)
                if len(data) != min(CHUNK, expected-offset) or hashlib.sha256(data).digest() != os.pread(journal, 32, offset // CHUNK * 32):
                    raise FileError("partial_changed", "The retained partial file failed verification.")
                hashed.update(data)
            os.ftruncate(fd, expected)
            os.ftruncate(journal, ((expected + CHUNK - 1) // CHUNK) * 32)
            os.fsync(fd)
            os.fsync(journal)
            return hashed.hexdigest()
        finally:
            os.close(fd)
            os.close(journal)


def commit(request, record, base, cancel=None):
    if record["state"] == "succeeded":
        return record
    if record["offset"] != record["size"] or record["state"] not in {"running", "committing"}:
        raise FileError("incomplete_transfer", "Receive and verify every chunk before commit.")
    root = request["root"]
    with stage(root, record) as (parent, folder):
        name = transfer_name(record)
        if record["state"] == "running":
            hashed = verify_prefix(root, record, cancel)
            if request.get("sha256") != hashed:
                raise FileError("digest_mismatch", "Source and destination digests do not match.")
            fd = opened(folder, b"data", os.O_RDONLY)
            try:
                regular(os.fstat(fd))
                record["committed_identity"] = identity(os.fstat(fd))
                os.fsync(fd)
            finally:
                os.close(fd)
            expected = record["expected"]
            if expected:
                checked_at(parent, name, expected)
            else:
                try:
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise FileError("destination_changed", "A file now occupies the destination.")
            check_cancel(cancel)
            record.update(state="committing", sha256=hashed)
            save(base, record)
            rename(folder, b"data", parent, name, 2 if expected else 1)
            os.fsync(parent)
            os.fsync(folder)
        fd = opened(parent, name, os.O_RDONLY)
        try:
            if not same(identity(os.fstat(fd)), record["committed_identity"], True) or file_hash(fd, cancel=cancel) != record["sha256"]:
                raise FileError("outcome_unknown", "The committed destination requires manual recovery.")
        finally:
            os.close(fd)
        if record["expected"]:
            old = identity(os.stat(b"data", dir_fd=folder, follow_symlinks=False))
            if not same(old, record["expected"], True):
                raise FileError("outcome_unknown", "A displaced object was retained for recovery.")
        record.update(state="succeeded", cleanup_pending=True)
        save(base, record)
    try:
        cleanup(root, record, base)
    except (OSError, FileError):
        pass
    return record


def cleanup(root, record, base):
    if not record.get("cleanup_pending"):
        return
    try:
        with stage(root, record) as (parent, folder):
            try:
                old = identity(os.stat(b"data", dir_fd=folder, follow_symlinks=False))
            except FileNotFoundError:
                old = None
            if old:
                if not record["expected"] or not same(old, record["expected"], True):
                    raise FileError("outcome_unknown", "A displaced object was retained for recovery.")
                os.unlink(b"data", dir_fd=folder)
            try:
                os.unlink(b"chunks", dir_fd=folder)
            except FileNotFoundError:
                pass
            os.fsync(folder)
            os.rmdir(record["stage"].encode(), dir_fd=parent)
            os.fsync(parent)
    except FileNotFoundError:
        pass
    record["cleanup_pending"] = False
    save(base, record)


def dispatch(request, data=b"", state_dir=None, cancel=None):
    with locked(request, state_dir) as base:
        if request["action"] == "transfer.begin":
            return summary(begin(request, base))
        record = load(base, request["transfer_id"])
        if not record or record.get("root_id") != request["root"]["id"]:
            raise FileError("transfer_missing", "The transfer receipt is unavailable.")
        action = request["action"]
        if action == "transfer.write":
            record = write_chunk(request, data, record, base)
        elif action == "transfer.resume":
            record = prepare(request["root"], record, base)
            if record["state"] not in {"running", "interrupted"}:
                raise FileError("transfer_state", "The transfer cannot be resumed.")
            record["prefix_sha256"] = verify_prefix(request["root"], record, cancel)
            record["state"] = "running"
            save(base, record)
        elif action == "transfer.commit":
            record = commit(request, record, base, cancel)
        elif action == "transfer.cancel":
            if record["state"] == "committing":
                raise FileError("outcome_unknown", "Reconcile the commit before cleanup.")
            if record["state"] == "succeeded":
                cleanup(request["root"], record, base)
                if request.get("discard_partial") and record.get("export"):
                    with entry_fd(request["root"], record["parent"], os.O_RDONLY | os.O_DIRECTORY) as parent:
                        name = transfer_name(record)
                        current = identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        if not same(current, record["committed_identity"], True):
                            raise FileError("source_changed", "The prepared download changed.")
                        os.unlink(name, dir_fd=parent)
                        os.fsync(parent)
                    record["state"] = "cancelled"
                    save(base, record)
            elif record["state"] not in TERMINAL:
                if request.get("discard_partial"):
                    discard(request["root"], record, base)
                elif record["state"] != "discarding":
                    record["prepared"] = record.get("prepared", record["state"] != "preparing")
                    record["state"] = "interrupted"
                    save(base, record)
        elif action not in {"transfer.status", "transfer.verify"}:
            raise FileError("invalid_action", "The transfer action is unsupported.")
        elif action == "transfer.verify":
            record["prefix_sha256"] = verify_prefix(request["root"], record, cancel)
        return summary(record)
