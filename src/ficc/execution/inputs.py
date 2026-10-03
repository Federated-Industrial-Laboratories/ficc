# SPDX-License-Identifier: Apache-2.0
"""Stage immutable input streams inside reserved storage without blocking lease monitoring."""

import errno
import hashlib
import os
import shutil
import stat
from pathlib import Path

from .files import directory, identity
from .ledger import Conflict
from .storage import mount_rows


class InputFailure(Conflict):
    """An input can no longer become the declared immutable object."""


def references(ctx):
    return [item for item in ctx["plan"]["job"]["inputs"] if item.get("delivery", "local") == "stream"]


def root(ctx):
    return Path(ctx["slot"]["mount"]) / (".inputs-" + ctx["plan"]["attempt_id"])


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def capabilities(ctx, progress):
    return [{**item, "path": str(root(ctx) / item["id"]), "identity": progress[item["id"]]["identity"]}
            for item in references(ctx) if progress.get(item["id"], {}).get("complete")]


def complete(ctx, progress):
    return all(progress.get(item["id"], {}).get("complete") for item in references(ctx))


class Inputs:
    def __init__(self):
        self.hashes = {}

    def initialize(self, ctx):
        check = ctx["check"]
        check()
        path = root(ctx)
        directory(path.parent, owner=os.getuid())
        if path.parent.stat().st_dev != ctx["binding"]["device"]:
            raise InputFailure("input_storage_changed")
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        progress = {}
        for item in references(ctx):
            check()
            value = hashlib.sha256()
            done = item["bytes"] == 0
            if done and item["digest"] != "sha256:" + value.hexdigest():
                raise InputFailure("input_digest_mismatch")
            fd = os.open(path / item["id"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                os.fchown(fd, os.getuid(), ctx["slot"]["gid"])
                os.fchmod(fd, 0o440 if done else 0o600)
                os.fsync(fd)
                progress[item["id"]] = {"offset": 0, "complete": done, "identity": identity(os.fstat(fd))}
            finally:
                os.close(fd)
            self.hashes[(ctx["plan"]["attempt_id"], item["id"])] = value
        sync_directory(path)
        sync_directory(path.parent)
        check()
        return progress

    def write(self, ctx, item, receipt, request, data):
        key = (request.attempt_id, item["id"])
        value = self.hashes.get(key)
        if value is None:
            raise InputFailure("input_state_unavailable")
        changed = value.copy()
        changed.update(data)
        offset = receipt["offset"] + len(data)
        done = offset == item["bytes"]
        if done and "sha256:" + changed.hexdigest() != item["digest"]:
            raise InputFailure("input_digest_mismatch")
        check = ctx["check"]
        check()
        path = root(ctx)
        directory(path, owner=os.getuid(), private=True)
        fd = os.open(path / item["id"], os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                    or identity(before) != receipt["identity"] or before.st_size != receipt["offset"]
                    or before.st_dev != ctx["binding"]["device"]):
                raise InputFailure("input_storage_changed")
            position = 0
            while position < len(data):
                check()
                written = os.pwrite(fd, memoryview(data)[position:], receipt["offset"] + position)
                if written == 0:
                    raise OSError(errno.EIO, "The input write made no progress.")
                position += written
            if done:
                os.fchmod(fd, 0o440)
            os.fsync(fd)
            saved = {"offset": offset, "complete": done, "identity": identity(os.fstat(fd))}
            check()
            return saved, changed
        finally:
            os.close(fd)

    def committed(self, asked, value):
        self.hashes[(asked.attempt_id, asked.object)] = value

    def release(self, ctx):
        path = root(ctx)
        if path.exists() or path.is_symlink():
            directory(path, owner=os.getuid(), private=True)
            if path.stat().st_dev != ctx["binding"]["device"]:
                raise ValueError("The input storage no longer belongs to its reservation.")
            if any(row["target"] == str(path) or row["target"].startswith(str(path) + "/") for row in mount_rows()):
                raise ValueError("The input storage still has a host mount. Keep its reservation.")
            if not shutil.rmtree.avoids_symlink_attacks:
                raise ValueError("This platform cannot safely remove staged input storage.")
            shutil.rmtree(path)
            sync_directory(path.parent)
        for key in list(self.hashes):
            if key[0] == ctx["plan"]["attempt_id"]:
                del self.hashes[key]
