# SPDX-License-Identifier: Apache-2.0
"""Dispatch bounded file metadata and binary chunk requests."""

import hashlib
import os
import stat

from . import file_actions, file_transfer
from .file_access import CHUNK, FileError, entry_fd, file_hash, identity, regular, same


def dispatch(request, data=b"", state_dir=None, cancel=None):
    if request.get("version") != "3" or not isinstance(data, bytes) or len(data) > CHUNK:
        raise FileError("invalid_request", "The file request is invalid.")
    action, root = request["action"], request["root"]
    if data and action != "transfer.write":
        raise FileError("invalid_request", "This request cannot contain file bytes.")
    if action == "file.root":
        return file_actions.probe(root), b""
    if action == "file.list":
        return file_actions.listing(root, request["entry"], request.get("cursor"), request.get("limit", 100)), b""
    if action == "file.breadcrumbs":
        return file_actions.breadcrumbs(root, request["entry"]), b""
    if action == "file.stat":
        return file_actions.inspect(root, request["entry"]), b""
    if action == "file.destination":
        return file_actions.destination(root, request), b""
    if action == "file.validate":
        return file_actions.validate(root, request["mutation"]), b""
    if action == "file.preview":
        return file_actions.preview(root, request["entry"], request.get("limit", 65536)), b""
    if action == "file.mutate":
        return file_actions.mutate(request, state_dir), b""
    if action.startswith("transfer."):
        return file_transfer.dispatch(request, data, state_dir, cancel), b""
    if action in {"file.read", "file.hash"}:
        if request["entry"]["identity"]["type"] != stat.S_IFREG:
            raise FileError("unsupported_file", "Select a regular file for transfer.")
        with entry_fd(root, request["entry"]) as fd:
            regular(os.fstat(fd))
            before = identity(os.fstat(fd))
            if action == "file.hash":
                return {"sha256": file_hash(fd, cancel=cancel), "size": before["size"]}, b""
            offset = request["offset"]
            limit = request.get("limit", CHUNK)
            if type(offset) is not int or not 0 <= offset <= before["size"] or type(limit) is not int or not 1 <= limit <= CHUNK:
                raise FileError("invalid_offset", "The requested file range is invalid.")
            data = os.pread(fd, limit, offset)
            if not same(before, identity(os.fstat(fd))):
                raise FileError("source_changed", "The source changed during reading.")
            return {"offset": offset, "next_offset": offset + len(data), "sha256": hashlib.sha256(data).hexdigest()}, data
    raise FileError("invalid_action", "The file action is unsupported.")
