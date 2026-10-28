# SPDX-License-Identifier: Apache-2.0
"""Bounded immutable object storage with resumable writes and atomic publication."""
import asyncio
import hashlib
import os
import shutil
import stat
import threading
from pathlib import Path

from ..errors import Failure
from ..settings import private_directory

CHUNK = 1024 * 1024
WRITE_CHUNK = 16 * CHUNK


class Cache:
    def __init__(self, root):
        self.root = Path(root)
        private_directory(self.root)
        self.binding = (self.root.stat().st_dev, self.root.stat().st_ino)
        self.lock = threading.RLock()

    def check(self):
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self.binding or info.st_uid != os.getuid():
            raise Failure("model_storage_changed", "The configured model volume is absent or has changed.", 409)

    def path(self, item, partial=False):
        self.check()
        return self.root / (item.digest.removeprefix("sha256:") + (".partial" if partial else ".blob"))

    def status(self, item):
        # Immutable publication is one rename. Readers must never queue behind a
        # large object's final digest verification on a controller event loop.
        for partial in (False, True, False):
            path = self.path(item, partial)
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > item.bytes:
                raise Failure("model_storage_changed", "A cached model object has an invalid identity.", 409)
            complete = not partial
            if complete and info.st_size != item.bytes:
                raise Failure("model_size", "The cached model size differs from its manifest.", 409)
            return {"offset": info.st_size, "complete": complete, "bytes": item.bytes}
        return {"offset": 0, "complete": False, "bytes": item.bytes}

    def write(self, item, offset, data):
        if (not data and offset != item.bytes) or len(data) > WRITE_CHUNK or offset + len(data) > item.bytes:
            raise Failure("model_range", "Write at most 16 MiB within the file; an empty final chunk verifies its retained bytes.", 422)
        with self.lock:
            status = self.status(item)
            if status["complete"]:
                return status
            if status["offset"] != offset:
                raise Failure("model_offset", "Resume at the current durable model offset.", 409)
            if not data:
                # A crash can leave the final fsynced bytes before publication.
                # Resume verification in the same off-thread, cancellable owner.
                self.publish(item)
                return self.status(item)
            # Reserve the remaining file before accepting its first byte. Physical free space
            # also includes other partially downloaded objects; no sparse preallocation.
            if shutil.disk_usage(self.root).free < item.bytes - offset + 64 * 1024 * 1024:
                raise Failure("model_capacity", "The model volume lacks space for this file and its reserve.", 409)
            path = self.path(item, True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size != offset or info.st_nlink != 1 or info.st_uid != os.getuid():
                    raise Failure("model_storage_changed", "The partial model changed during upload.", 409)
                view = memoryview(data)
                while view:
                    written = os.pwrite(fd, view, offset)
                    if not written:
                        raise OSError("Model write made no progress.")
                    offset += written
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            if offset == item.bytes:
                self.publish(item)
            return self.status(item)

    async def write_async(self, item, offset, data):
        # Cancellation must not release an upload slot while its thread still
        # owns bytes or is making the acknowledged offset durable.
        work = asyncio.create_task(asyncio.to_thread(self.write, item, offset, data))
        cancelled = False
        while True:
            try:
                result = await asyncio.shield(work)
                break
            except asyncio.CancelledError:
                if work.cancelled():
                    raise
                cancelled = True
            except Exception:
                if cancelled:
                    raise asyncio.CancelledError from None
                raise
        if cancelled:
            raise asyncio.CancelledError
        return result

    def publish(self, item):
        path = self.path(item, True)
        with path.open("rb") as source:
            actual = hashlib.file_digest(source, "sha256").hexdigest()
        if "sha256:" + actual != item.digest:
            path.unlink()
            raise Failure("model_digest", "The complete model digest did not match; the partial object was discarded.", 409)
        path.chmod(0o400)
        os.replace(path, self.path(item))
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(self, item, offset, length):
        if not self.status(item)["complete"]:
            raise Failure("model_missing", "Complete all model files before starting inference.", 409)
        fd = os.open(self.path(item), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size != item.bytes or info.st_mode & 0o222:
                raise Failure("model_storage_changed", "The published model object changed identity.", 409)
            return os.pread(fd, min(WRITE_CHUNK, length), offset)
        finally:
            os.close(fd)

    def evict(self, item):
        if not self.lock.acquire(blocking=False):
            raise Failure("model_busy", "Wait for the current model write or verification before eviction.", 409)
        try:
            self.path(item).unlink(missing_ok=True)
            self.path(item, True).unlink(missing_ok=True)
        finally:
            self.lock.release()
