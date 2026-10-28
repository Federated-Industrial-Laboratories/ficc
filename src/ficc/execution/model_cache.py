# SPDX-License-Identifier: Apache-2.0
"""Optional finite node cache; immutable copies remain below each attempt's storage lease."""
import concurrent.futures
import fcntl
import hashlib
import os
import secrets
import stat
import threading
from pathlib import Path

from .files import directory, identity
from .process import command
from .storage import mount_rows


class ModelCache:
    def __init__(self, configuration, retained):
        self.configuration, self.retained = configuration, retained
        self.root = Path(configuration.directory)
        self.lock = threading.RLock()
        self.pending = set()
        self.pending_lock = threading.Lock()
        self.binding = self.verify()
        self.lease = os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(self.lease)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                raise ValueError("The node model cache lock is not private.")
            try:
                fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("The node model cache is in use by another supervisor or administrator.") from exc
            self.verify()
            for path in self.root.glob("*.partial"):
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        except BaseException:
            os.close(self.lease)
            raise

    def verify(self):
        info = directory(self.root, private=True)
        rows = [row for row in mount_rows() if str(self.root) == row["target"] or str(self.root).startswith(row["target"].rstrip("/") + "/")]
        row = max(rows, key=lambda value: len(value["target"]))
        uuid = command(["/usr/sbin/blkid", "-s", "UUID", "-o", "value", "/dev/block/" + row["device"]])["stdout"].strip()
        if uuid != self.configuration.filesystem_uuid:
            raise ValueError("The node model cache filesystem is absent or has changed.")
        value = (info.st_dev, info.st_ino)
        if hasattr(self, "binding") and self.binding != value:
            raise ValueError("The node model cache directory identity changed.")
        return value

    def name(self, ctx, item):
        return ctx["plan"]["project_id"] + "-" + item["digest"].removeprefix("sha256:") + ".blob"

    def copy(self, source, destination, item, check, gid, source_owner=0):
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != source_owner or before.st_size != item["bytes"] or before.st_mode & 0o022:
                raise ValueError("A model cache source changed identity.")
            hashed, count, pending = hashlib.sha256(), 0, 0
            while data := os.read(source_fd, 1024 * 1024):
                check()
                hashed.update(data)
                count += len(data)
                view = memoryview(data)
                while view:
                    written = os.write(output, view)
                    if not written:
                        raise OSError("Cache copy made no progress.")
                    view = view[written:]
                pending += len(data)
                if pending >= 16 * 1024 * 1024:
                    os.fdatasync(output)
                    os.posix_fadvise(output, 0, 0, os.POSIX_FADV_DONTNEED)
                    os.posix_fadvise(source_fd, 0, 0, os.POSIX_FADV_DONTNEED)
                    pending = 0
            if count != item["bytes"] or "sha256:" + hashed.hexdigest() != item["digest"] or identity(before) != identity(os.fstat(source_fd)):
                raise ValueError("The model cache source digest changed.")
            os.fchown(output, 0, gid)
            os.fchmod(output, 0o440 if gid else 0o400)
            os.fsync(output)
            os.posix_fadvise(source_fd, 0, 0, os.POSIX_FADV_DONTNEED)
            os.posix_fadvise(output, 0, 0, os.POSIX_FADV_DONTNEED)
            return identity(os.fstat(output))
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        finally:
            os.close(source_fd)
            os.close(output)

    def restore(self, ctx, item, destination):
        with self.lock:
            self.verify()
            source = self.root / self.name(ctx, item)
            if not source.exists():
                return None
            result = self.copy(source, destination, item, ctx["check"], ctx["slot"]["gid"])
            os.utime(source, None)
            return result

    def publish(self, ctx, item, source):
        name = self.name(ctx, item)
        with self.pending_lock:
            if name in self.pending or len(self.pending) >= 64:
                return
            self.pending.add(name)
        def work():
            temporary = self.root / (secrets.token_hex(16) + ".partial")
            try:
                with self.lock:
                    self.verify()
                    if (self.root / name).exists():
                        return
                    files = list(self.root.glob("*.blob"))
                    pinned = {self.name({"plan": value["plan"]}, entry) for value in self.retained()
                              for entry in value["plan"]["job"]["inputs"]}
                    total = sum(path.stat().st_size for path in files)
                    for path in sorted(files, key=lambda entry: entry.stat().st_mtime):
                        if total + item["bytes"] <= self.configuration.maximum_bytes and len(files) < self.configuration.maximum_files:
                            break
                        if path.name not in pinned:
                            total -= path.stat().st_size
                            path.unlink()
                            files.remove(path)
                    if total + item["bytes"] > self.configuration.maximum_bytes or len(files) >= self.configuration.maximum_files:
                        return
                    self.copy(source, temporary, item, ctx["check"], 0)
                    os.replace(temporary, self.root / name)
                    fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
            except (OSError, ValueError):
                # The verified attempt input remains authoritative if an optional cache fill fails.
                pass
            finally:
                temporary.unlink(missing_ok=True)
                with self.pending_lock:
                    self.pending.discard(name)
        self.pool.submit(work)

    def close(self):
        try:
            self.pool.shutdown(wait=True, cancel_futures=True)
        finally:
            os.close(self.lease)
