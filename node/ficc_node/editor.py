# SPDX-License-Identifier: Apache-2.0
"""Read bounded text and retain editor recovery through the file channel."""

import hashlib
import os
import stat
from contextlib import contextmanager

from .file_access import (
    CHUNK,
    FileError,
    check_cancel,
    entry_fd,
    identity,
    opened,
    parent_fd,
    parts,
    reference,
    same,
)
from .file_state import load, locked, record_path, save
from .job_state import digest

MAX_TEXT = CHUNK
MAX_RETAINED = 128 * 1024 * 1024
MAX_EDITS = 128


def text_bytes(data):
    if not isinstance(data, bytes) or len(data) > MAX_TEXT or b"\0" in data:
        raise FileError("editor_text", "Select UTF-8 text no larger than 256 KiB, without NUL bytes.")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise FileError("editor_text", "The file is not UTF-8 text.") from None
    return data


def read_fd(fd):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_TEXT:
        raise FileError("editor_type", "Select a regular text file no larger than 256 KiB.")
    data = os.pread(fd, MAX_TEXT + 1, 0)
    if not same(identity(before), identity(os.fstat(fd))) or len(data) != before.st_size:
        raise FileError("editor_changed", "The file changed while it was read.")
    return text_bytes(data), before


def editable(fd, info):
    return (info.st_uid == os.getuid() and info.st_nlink == 1 and not info.st_mode & 0o7000
            and not os.listxattr(fd))


def read_text(root, entry):
    with entry_fd(root, entry) as fd:
        data, info = read_fd(fd)
        return {"sha256": hashlib.sha256(data).hexdigest(), "revision": digest(identity(info)),
                "size": len(data), "mode": stat.S_IMODE(info.st_mode),
                "editable": editable(fd, info) and not root.get("read_only", False)}, data


@contextmanager
def stage(root, record):
    with parent_fd(root, record["entry"]) as (parent, name):
        folder = opened(parent, record["stage"].encode(), os.O_RDONLY | os.O_DIRECTORY)
        try:
            info = os.fstat(folder)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise FileError("editor_recovery", "The retained edit directory changed.")
            yield parent, name, folder
        finally:
            os.close(folder)


def receipt(record):
    return {key: record.get(key) for key in ("id", "state", "retained", "resolved", "message", "sha256", "reference")}


def original_matches(fd, record):
    data, info = read_fd(fd)
    expected = record["entry"]["identity"]
    return (all(identity(info)[key] == expected[key] for key in ("dev", "ino", "type", "size", "mtime_ns"))
            and hashlib.sha256(data).hexdigest() == record["expected_sha256"]
            and stat.S_IMODE(info.st_mode) == record["mode"] and editable(fd, info)
            and (info.st_uid, info.st_gid) == (record["uid"], record["gid"]))


def inspect_result(root, record, base):
    if record["state"] == "preparing":
        record.update(state="failed", message="The save stopped before publication. Recover the retained draft.")
        try:
            with parent_fd(root, record["entry"]) as (parent, _):
                try:
                    os.stat(record["stage"], dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    record.update(retained=False, message="The save stopped before creating recovery files.")
        except (OSError, FileError):
            pass
        save(base, record)
    if record["state"] != "unknown" or not record.get("published_identity"):
        return record
    try:
        with stage(root, record) as (parent, name, folder):
            current = opened(parent, name, os.O_RDONLY | os.O_NONBLOCK)
            old = None
            try:
                old = opened(folder, b"replacement", os.O_RDONLY | os.O_NONBLOCK)
                data, info = read_fd(current)
                if not same(identity(info), record["published_identity"], True) or hashlib.sha256(data).hexdigest() != record["sha256"]:
                    replacement, replacement_info = read_fd(old)
                    if (same(identity(replacement_info), record["published_identity"], True)
                            and hashlib.sha256(replacement).hexdigest() == record["sha256"]
                            and original_matches(current, record)):
                        record.update(state="failed", message="Publication did not complete. The submitted draft is retained.")
                        save(base, record)
                    return record
                if not original_matches(old, record):
                    record.update(state="conflict", message="The replacement was published, but another edit was retained. Recover both copies.")
                else:
                    record.update(state="succeeded", message="Saved. The prior file and submitted text are retained.",
                                  reference=reference(current, parts(record["entry"]), parent))
            finally:
                os.close(current)
                if old is not None:
                    os.close(old)
    except (OSError, FileError):
        return record
    save(base, record)
    return record


def recovery(root, record, kind):
    if not record.get("retained") or kind not in {"draft", "original"}:
        raise FileError("editor_recovery", "The retained copy is not available.")
    if kind == "original" and record["state"] not in {"succeeded", "conflict"}:
        raise FileError("editor_unknown", "The save outcome is not resolved. Keep all recovery files.")
    with stage(root, record) as (_, _, folder):
        fd = opened(folder, b"draft" if kind == "draft" else b"replacement", os.O_RDONLY | os.O_NONBLOCK)
        try:
            data, _ = read_fd(fd)
            return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}, data
        finally:
            os.close(fd)


def cleanup(root, record, base, resolved=False):
    if root.get("read_only"):
        raise FileError("read_only", "This root is read-only.")
    if record["state"] == "unknown" or record["state"] == "preparing":
        raise FileError("editor_unknown", "Resolve the save outcome before removing retained copies.")
    if record["state"] == "conflict" and not record.get("resolved"):
        if not resolved:
            raise FileError("editor_conflict", "Recover both copies and confirm recovery first.")
        recovery(root, record, "original")
        recovery(root, record, "draft")
        record["resolved"] = True
        save(base, record)
    if not record.get("retained"):
        return record
    try:
        return remove_stage(root, record, base)
    except FileNotFoundError:
        if not record.get("resolved"):
            raise
        with parent_fd(root, record["entry"]) as (parent, _):
            try:
                os.stat(record["stage"], dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                os.fsync(parent)
                record["retained"] = False
                save(base, record)
                return record
        raise


def remove_stage(root, record, base):
    with stage(root, record) as (parent, _, folder):
        names = os.listdir(folder)
        if set(names) - {"draft", "replacement"}:
            raise FileError("editor_recovery", "The recovery directory contains an unknown object.")
        for name in names:
            info = os.stat(name, dir_fd=folder, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise FileError("editor_recovery", "A retained object requires manual recovery.")
        record["resolved"] = True
        save(base, record)
        for name in names:
            os.unlink(name, dir_fd=folder)
        os.fsync(folder)
        os.rmdir(record["stage"].encode(), dir_fd=parent)
        os.fsync(parent)
    record["retained"] = False
    save(base, record)
    return record


def dispatch(request, data=b"", state_dir=None, cancel=None):
    action, root = request["action"], request["root"]
    check_cancel(cancel)
    if action == "editor.read":
        return read_text(root, request["entry"])
    with locked(request, state_dir) as base:
        if action == "editor.save":
            from .editor_save import commit
            return receipt(commit(request, data, base, cancel)), b""
        record = load(base, request["operation_id"])
        if action == "editor.forget" and record is None:
            return {"id": request["operation_id"], "removed": True}, b""
        if not record or record.get("kind") != "editor" or record.get("root_id") != root["id"]:
            raise FileError("editor_missing", "The edit receipt is not available.")
        if action == "editor.forget":
            if root.get("read_only") or record["state"] in {"preparing", "unknown"} or record.get("retained"):
                raise FileError("editor_retained", "Resolve and remove retained copies before removing this receipt.")
            record_path(base, record["id"]).unlink()
            folder = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(folder)
            finally:
                os.close(folder)
            return {"id": record["id"], "removed": True}, b""
        if action == "editor.status":
            return receipt(inspect_result(root, record, base)), b""
        if action == "editor.recovery":
            return recovery(root, record, request["copy"])
        if action == "editor.cleanup":
            if request.get("confirm") is not True:
                raise FileError("confirmation_required", "Confirm removal of the retained copies.")
            return receipt(cleanup(root, record, base, request.get("recovered") is True)), b""
    raise FileError("invalid_action", "The editor action is not supported.")
