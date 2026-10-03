# SPDX-License-Identifier: Apache-2.0
"""Reserve incremental output capacity and atomically publish verified exports."""

import hashlib
import os

from ficc_node.file_access import CHUNK, entry_fd, identity, new_name, reference, rename, same
from ficc_node.file_manifest import reserve

from .errors import Failure


class Output:
    def __init__(self, service, destination, filename, operation_id, actor, limits, retain=None):
        self.service, self.actor, self.limits = service, actor, limits
        self.root, self.parent = service.files.resolve(destination["root_id"], destination["entry_id"], actor, "files:write")
        if self.root.get("node_id") is not None:
            raise Failure("destination_local", "Select a controller registered root for this export. Transfer the completed dataset to another node afterwards.", 409)
        self.name, self.temporary = new_name(filename), (".ficc-source-" + operation_id + ".partial").encode()
        self.directory = self.file = None
        self.size = self.reserved = 0
        self.hash = hashlib.sha256()
        self.published = False
        self.owned = False
        retained = {"root_id": self.root["id"], "root_revision": self.root["revision"], "parent": self.parent,
                    "filename": filename, "identity": None, "cleanup": "pending"}
        if retain:
            retain(retained)
        try:
            with entry_fd(self.root, self.parent, os.O_RDONLY | os.O_DIRECTORY) as fd:
                self.directory = os.dup(fd)
            self.file = os.open(self.temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
            self.owned = True
            retained["identity"] = identity(os.fstat(self.file))
            if retain:
                retain(retained)
        except BaseException:
            self.close()
            raise

    def write(self, chunk):
        assert self.file is not None
        self.service.files.check(self.actor, "files:write", self.root)
        if not isinstance(chunk, bytes) or not 0 < len(chunk) <= CHUNK:
            raise Failure("stream_limit", "The source returned an invalid output chunk.", 502)
        maximum = self.limits["export_bytes"]
        end = self.size + len(chunk)
        if maximum is not None and end > maximum:
            raise Failure("export_quota", "The export exceeds the configured byte quota.", 409)
        if end > self.reserved:
            space = os.fstatvfs(self.file)
            required = ((end + CHUNK - 1) // CHUNK) * CHUNK
            if space.f_bavail * space.f_frsize - (required - self.reserved) < self.limits["free_bytes"]:
                raise Failure("disk_capacity", "The export cannot reserve space while retaining configured disk headroom.", 409)
            reserve(self.file, required)
            self.reserved = required
        offset = 0
        while offset < len(chunk):
            offset += os.write(self.file, chunk[offset:])
        self.hash.update(chunk)
        self.size = end

    def publish(self):
        assert self.file is not None and self.directory is not None
        self.service.files.check(self.actor, "files:write", self.root)
        with entry_fd(self.root, self.parent, os.O_RDONLY | os.O_DIRECTORY):
            pass
        os.ftruncate(self.file, self.size)
        os.fsync(self.file)
        rename(self.directory, self.temporary, self.directory, self.name)
        self.published = True
        os.fsync(self.directory)
        from ficc_node.file_access import encode
        ref = reference(self.file, [], self.directory)
        ref["parts"] = [*self.parent["parts"], encode(self.name)]
        return {"root_id": self.root["id"], "entry_id": self.service.files.refs.issue(self.root, ref)}

    def close(self):
        if self.file is not None:
            os.close(self.file)
            self.file = None
        if self.directory is not None:
            if self.owned and not self.published:
                try:
                    os.unlink(self.temporary, dir_fd=self.directory)
                    os.fsync(self.directory)
                except FileNotFoundError:
                    pass
            os.close(self.directory)
            self.directory = None


def cleanup(service, value, actor):
    """Remove only a retained run's partial inode; never unlink its final output."""
    retained = value.get("staging")
    if not retained:
        return
    root = service.files.store.root(retained["root_id"])
    service.files.check(actor, "files:write", root)
    if root["revision"] != retained["root_revision"] or root.get("node_id") is not None:
        raise Failure("cleanup_source_changed", "The export destination approval changed; cleanup remains pending.", 409)
    temporary = (".ficc-source-" + value["id"] + ".partial").encode()
    with entry_fd(root, retained["parent"], os.O_RDONLY | os.O_DIRECTORY) as directory:
        try:
            fd = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            retained["cleanup"] = "no_partial"
            return
        try:
            if retained["identity"] is None or not same(identity(os.fstat(fd)), retained["identity"], directory=True):
                raise Failure("cleanup_source_changed", "The partial output identity differs; cleanup remains pending.", 409)
            # The directory and file are both pinned; refuse a substituted name.
            if os.stat(temporary, dir_fd=directory, follow_symlinks=False).st_ino != os.fstat(fd).st_ino:
                raise Failure("cleanup_source_changed", "The partial output name changed; cleanup remains pending.", 409)
            os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
            retained["cleanup"] = "partial_removed"
        finally:
            os.close(fd)
