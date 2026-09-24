# SPDX-License-Identifier: Apache-2.0
"""List ordinary entries and apply confirmed descriptor-relative mutations."""

import base64
import json
import os
import stat

from .file_access import (
    FileError,
    change_mode,
    checked_at,
    decode,
    display,
    encode,
    entry_fd,
    identity,
    mode_supported,
    new_name,
    opened,
    parent_fd,
    parts,
    reference,
    regular,
    rename,
    root_fd,
    same,
    sync_filesystem,
    transfer_name,
)
from .file_state import load, locked, save
from .job_state import digest


def probe(root):
    with root_fd(root) as fd:
        info = os.fstat(fd)
        if info.st_uid != os.getuid():
            raise FileError("invalid_root", "The root must be owned by the current account.")
        return {"identity": identity(info), "reference": reference(fd, []), "mode_supported": mode_supported(), "owner_uid": os.getuid()}


def breadcrumbs(root, ref):
    values = parts(ref)
    result = []
    with root_fd(root) as root_handle:
        result.append({"name": root.get("label", "/"), "reference": reference(root_handle, [])})
        parent = os.dup(root_handle)
        try:
            for index, name in enumerate(values):
                fd = opened(root_handle, b"/".join(values[:index+1]), os.O_RDONLY | os.O_DIRECTORY)
                result.append({"name": display(name), "reference": reference(fd, values[:index+1], parent)})
                os.close(parent)
                parent = fd
        finally:
            os.close(parent)
    return {"entries": result}


def info_value(info, name, ref):
    kind = "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else (
        "symlink" if stat.S_ISLNK(info.st_mode) else "special")
    return {"name": display(name), "kind": kind, "size": info.st_size,
            "modified_ns": info.st_mtime_ns, "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode), "reference": ref, "revision": digest(identity(info))}


def listing(root, ref, cursor=None, limit=100):
    if type(limit) is not int or not 1 <= limit <= 200:
        raise FileError("invalid_limit", "The listing limit is invalid.")
    with entry_fd(root, ref, os.O_RDONLY | os.O_DIRECTORY) as fd:
        before = identity(os.fstat(fd))
        revision = digest(before)
        after = b""
        if cursor:
            if not isinstance(cursor, dict) or cursor.get("revision") != revision:
                raise FileError("stale_cursor", "The directory changed. Refresh its first page.")
            after = decode(cursor["after"])
        names = []
        with os.scandir(fd) as scan:
            for count, entry in enumerate(scan, 1):
                if count > 10000:
                    raise FileError("directory_limit", "The directory exceeds 10,000 entries.")
                name = os.fsencode(entry.name)
                if not name.startswith(b".ficc-") and name > after:
                    names.append(name)
                    if len(names) > limit + 1:
                        names.sort()
                        names.pop()
        names.sort()
        result: list[dict] = []
        response_bytes = 0
        for name in names[:limit]:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            child = {"parts": ref["parts"] + [encode(name)], "identity": identity(info), "parent": before}
            value = info_value(info, name, child)
            length = len(json.dumps(value).encode())
            if result and response_bytes + length > 524288:
                break
            response_bytes += length
            result.append(value)
        if not same(before, identity(os.fstat(fd))):
            raise FileError("stale_cursor", "The directory changed during listing.")
        return {"entries": result, "next_cursor": {"revision": revision, "after": encode(names[len(result)-1])}
                if len(names) > len(result) else None}


def inspect(root, ref):
    if not ref["parts"]:
        with entry_fd(root, ref, os.O_RDONLY | os.O_DIRECTORY) as fd:
            return info_value(os.fstat(fd), b"/", reference(fd, []))
    with parent_fd(root, ref) as (fd, name):
        checked_at(fd, name, ref["identity"])
        return info_value(os.stat(name, dir_fd=fd, follow_symlinks=False), name, ref)


def destination(root, request):
    with entry_fd(root, request["parent"], os.O_RDONLY | os.O_DIRECTORY) as fd:
        name = transfer_name(request)
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return {"identity": None, "kind": None}
        return {"identity": identity(info), "kind": "file" if stat.S_ISREG(info.st_mode) else "other"}


def validate(root, mutation):
    action = mutation["action"]
    if root.get("read_only"):
        raise FileError("read_only", "This root is read-only.")
    if action in {"mkdir", "rename"}:
        result = destination(root, {"parent": mutation["parent"], "name": mutation["name"]})
        if result["identity"]:
            raise FileError("destination_conflict", "The destination name already exists.")
    if action == "mkdir":
        return {"valid": True}
    ref = mutation["entry"]
    value = inspect(root, ref)
    if not ref["parts"] or value["kind"] == "special":
        raise FileError("unsupported_file", "The selected entry cannot be changed.")
    if action == "delete" and value["kind"] == "directory":
        with entry_fd(root, ref, os.O_RDONLY | os.O_DIRECTORY) as fd, os.scandir(fd) as entries:
            if next(entries, None) is not None:
                raise FileError("directory_not_empty", "Only empty directories can be deleted.")
    if action == "mode":
        if not mode_supported():
            raise FileError("mode_unavailable", "The kernel does not support descriptor mode changes.")
        with entry_fd(root, ref, os.O_PATH) as fd:
            info = os.fstat(fd)
            if (value["kind"] not in {"file", "directory"} or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o7000 or (value["kind"] == "file" and info.st_nlink != 1)):
                raise FileError("mode_refused", "This object does not permit a mode change.")
    return {"valid": True}


def preview(root, ref, limit=65536):
    if type(limit) is not int or not 1 <= limit <= 65536:
        raise FileError("invalid_limit", "The preview limit is invalid.")
    if ref["identity"]["type"] != stat.S_IFREG:
        raise FileError("unsupported_file", "Select a regular file for preview.")
    with entry_fd(root, ref) as fd:
        regular(os.fstat(fd))
        before = identity(os.fstat(fd))
        data = os.pread(fd, limit, 0)
        if not same(before, identity(os.fstat(fd))):
            raise FileError("source_changed", "The source changed during preview.")
        try:
            data.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            encoding = "binary"
        return {"data_base64": base64.b64encode(data).decode(), "bytes": len(data),
                "truncated": before["size"] > len(data), "encoding": encoding}


def mutate(request, state_dir=None):
    root, mutation = request["root"], request["mutation"]
    if root.get("read_only"):
        raise FileError("read_only", "This root is read-only.")
    action = mutation["action"]
    signature = digest({"root": root, "mutation": mutation})
    with locked(request, state_dir) as base:
        previous = load(base, request["operation_id"])
        if previous:
            if previous["digest"] != signature:
                raise FileError("idempotency_conflict", "The operation identity is already in use.")
            return previous
        result = {"id": request["operation_id"], "digest": signature, "state": "unknown", "result": None}
        save(base, result)
        if action == "mkdir":
            with entry_fd(root, mutation["parent"], os.O_RDONLY | os.O_DIRECTORY) as parent:
                name = new_name(mutation["name"])
                os.mkdir(name, mode=0o700, dir_fd=parent)
                os.fsync(parent)
        elif action == "mode":
            mode = mutation["mode"]
            if type(mode) is not int or not 0 <= mode <= 0o777:
                raise FileError("invalid_mode", "Use ordinary owner, group, and other mode bits.")
            with entry_fd(root, mutation["entry"], os.O_PATH) as fd:
                info = os.fstat(fd)
                if (not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                        or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o7000
                        or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                    raise FileError("mode_refused", "This object does not permit a mode change.")
                change_mode(fd, mode)
                with root_fd(root) as root_handle:
                    # An O_PATH handle permits mode repair but cannot be fsynced.
                    sync_filesystem(root_handle)
        elif action in {"rename", "delete"}:
            ref = mutation["entry"]
            with parent_fd(root, ref) as (parent, name):
                expected = checked_at(parent, name, ref["identity"])
                if expected["type"] not in {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}:
                    raise FileError("unsupported_file", "This object cannot be changed.")
                if action == "rename":
                    with entry_fd(root, mutation["parent"], os.O_RDONLY | os.O_DIRECTORY) as target:
                        rename(parent, name, target, new_name(mutation["name"]))
                        os.fsync(target)
                else:
                    quarantine = (".ficc-delete-" + result["id"]).encode()
                    rename(parent, name, parent, quarantine)
                    os.fsync(parent)
                    actual = identity(os.stat(quarantine, dir_fd=parent, follow_symlinks=False))
                    if not same(actual, expected, True):
                        raise FileError("outcome_unknown", "An unexpected object was retained for recovery.")
                    if expected["type"] == stat.S_IFDIR:
                        try:
                            os.rmdir(quarantine, dir_fd=parent)
                        except OSError:
                            rename(parent, quarantine, parent, name)
                            raise
                    else:
                        os.unlink(quarantine, dir_fd=parent)
                os.fsync(parent)
        else:
            raise FileError("invalid_action", "The file action is unsupported.")
        result.update(state="succeeded", result={"action": action})
        save(base, result)
        return result
