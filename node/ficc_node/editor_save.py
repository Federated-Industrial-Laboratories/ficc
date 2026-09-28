# SPDX-License-Identifier: Apache-2.0
"""Publish retained editor copies without claiming a filesystem compare-and-swap."""

import hashlib
import os
import stat

from .editor import (
    MAX_EDITS,
    MAX_RETAINED,
    MAX_TEXT,
    editable,
    inspect_result,
    read_fd,
    stage,
    text_bytes,
)
from .file_access import (
    FileError,
    check_cancel,
    checked_at,
    entry_fd,
    identity,
    parent_fd,
    rename,
    same,
)
from .file_state import identifier, load, save
from .job_state import digest, read


def capacity(base, reserved):
    count = 0
    total = reserved
    for path in base.glob("*.json"):
        record = read(path, 262144)
        if record.get("kind") != "editor" or not record.get("retained"):
            continue
        count += 1
        current = record["reserved_bytes"]
        try:
            with stage(record["root"], record) as (_, _, folder):
                actual = sum(os.stat(name, dir_fd=folder, follow_symlinks=False).st_size
                             for name in os.listdir(folder))
                current = max(current, actual)
        except (OSError, FileError) as exc:
            raise FileError("editor_capacity", "A retained edit cannot be measured. Restore its folder before saving more files.") from exc
        total += current
    if count >= MAX_EDITS or total > MAX_RETAINED:
        raise FileError("editor_capacity", "Recover and remove retained edit copies before saving more files.")


def write_file(folder, name, data, mode, expected=None, cancel=None):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=folder)
    try:
        offset = 0
        while offset < len(data):
            check_cancel(cancel)
            count = os.write(fd, data[offset:])
            if count <= 0:
                raise OSError("The edit write did not advance.")
            offset += count
        os.fchmod(fd, mode)
        info = os.fstat(fd)
        if os.listxattr(fd) or info.st_nlink != 1 or (expected and (info.st_uid, info.st_gid) != expected):
            raise FileError("editor_metadata", "The file owner, group or extended attributes cannot be preserved.")
        os.fsync(fd)
        return identity(info)
    finally:
        os.close(fd)


def commit(request, data, base, cancel=None):
    root, entry = request["root"], request["entry"]
    text_bytes(data)
    operation_id = identifier(request["operation_id"])
    checksum = request.get("expected_sha256")
    if not isinstance(checksum, str) or len(checksum) != 64 or any(char not in "0123456789abcdef" for char in checksum):
        raise FileError("editor_revision", "The text content fingerprint is invalid.")
    signature = digest({"root": root, "entry": entry, "expected_sha256": checksum,
                        "sha256": hashlib.sha256(data).hexdigest()})
    previous = load(base, operation_id)
    if previous:
        if previous.get("kind") != "editor" or previous["digest"] != signature:
            raise FileError("idempotency_conflict", "The edit identity belongs to another request.")
        return inspect_result(root, previous, base)
    if root.get("read_only"):
        raise FileError("read_only", "This root is read-only.")
    with entry_fd(root, entry) as fd:
        original, info = read_fd(fd)
        if not editable(fd, info):
            raise FileError("editor_metadata", "Edit only owned files with one link, ordinary mode bits and no extended attributes.")
        if hashlib.sha256(original).hexdigest() != checksum:
            raise FileError("editor_conflict", "The text changed. Reload it or keep your draft.")
    reserved = 3 * MAX_TEXT
    capacity(base, reserved)
    record = {"id": operation_id, "kind": "editor", "digest": signature,
              "root_id": root["id"], "root": root, "entry": entry,
              "stage": ".ficc-editor-" + operation_id, "mode": stat.S_IMODE(info.st_mode),
              "uid": info.st_uid, "gid": info.st_gid,
              "expected_sha256": checksum, "sha256": hashlib.sha256(data).hexdigest(),
              "reserved_bytes": reserved, "state": "preparing", "retained": True,
              "resolved": False, "message": "The edit is being prepared."}
    save(base, record)
    try:
        with parent_fd(root, entry) as (parent, name):
            checked_at(parent, name, entry["identity"])
            os.mkdir(record["stage"].encode(), 0o700, dir_fd=parent)
            os.fsync(parent)
        with stage(root, record) as (parent, name, folder):
            write_file(folder, b"draft", data, 0o600, cancel=cancel)
            record["published_identity"] = write_file(folder, b"replacement", data, record["mode"],
                                                       (info.st_uid, info.st_gid), cancel)
            os.fsync(folder)
            # The second read narrows the race. The displaced file is still retained.
            with entry_fd(root, entry) as current:
                prior, current_info = read_fd(current)
                if not same(identity(current_info), entry["identity"]) or hashlib.sha256(prior).hexdigest() != checksum:
                    raise FileError("editor_conflict", "The text changed. The submitted draft is retained.")
            checked_at(parent, name, entry["identity"])
            check_cancel(cancel)
            record.update(state="unknown", message="The replacement outcome needs inspection. Keep both copies.")
            save(base, record)
            rename(folder, b"replacement", parent, name, 2)
            os.fsync(parent)
            os.fsync(folder)
        return inspect_result(root, record, base)
    except (OSError, FileError) as exc:
        if record["state"] == "preparing":
            record.update(state="failed", message=getattr(exc, "message", "The file could not be saved. The draft is retained."))
            try:
                with stage(root, record):
                    pass
            except FileNotFoundError:
                record["retained"] = False
        save(base, record)
        return record
