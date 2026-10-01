# SPDX-License-Identifier: Apache-2.0
"""Pin an operator-selected local socket and verify its current process peer."""

import hashlib
import os
import secrets
import socket
import stat
import struct
import tempfile
from contextlib import contextmanager
from pathlib import Path

from ficc.errors import Failure
from ficc.modules.adapter_protocol import identity
from ficc.modules.validation import dumps, fields, loads, text
from ficc.modules.watcher import identity as process_identity

from .adapter_store import directory, read, write


def peer_record(stream, info):
    pid, uid, gid = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.getuid() or pid <= 0:
        raise Failure("adapter_binding_invalid", "The provider socket peer belongs to another account.")
    return {"device": info.st_dev, "inode": info.st_ino, "uid": uid, "pid": pid, "start": process_identity(pid)}


def path(value):
    result = text(value, 240)
    if not result.startswith("/") or any(part in {"", ".", ".."} for part in result.split("/")[1:]):
        raise Failure("adapter_binding_invalid", "Select one absolute local socket path.")
    return Path(result)


@contextmanager
def opened(value, *, handoff=False):
    source = path(value)
    # Refuse path aliases before opening. The open descriptor pins the selected inode.
    if source.resolve() != source.absolute():
        raise Failure("adapter_binding_invalid", "The provider socket path must not contain links.")
    fd = os.open(source, os.O_PATH | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise Failure("adapter_binding_invalid", "The provider socket must be owned and must not permit other accounts to write.")
        pinned = Path(f"/proc/{os.getpid()}/fd/{fd}")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(1)
            peer.connect(str(pinned))
            record = peer_record(peer, info)
            checksum = hashlib.sha256(dumps(record)).hexdigest()
            if not handoff:
                yield pinned, checksum
                return
            # An independent user service cannot access this process's /proc FD.
            # Hold the socket inode through an owned, same-filesystem hard link.
            parent = source.parent.stat()
            if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
                raise Failure("adapter_binding_invalid", "The provider socket requires an owned private directory.")
            with tempfile.TemporaryDirectory(prefix=".ficc-resource-", dir=source.parent) as temporary:
                staged = Path(temporary) / "socket"
                os.link(source, staged, follow_symlinks=False)
                linked = staged.lstat()
                if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
                    raise Failure("adapter_binding_changed", "The provider socket changed during resource handoff.")
                yield staged, checksum
    finally:
        os.close(fd)


def public(value, available):
    return {"id": value["id"], "resource_kind": "unix-stream", "available": available,
            "identity": value["identity"], "label": value["label"], "owner_uid": os.getuid()}


def register(base, parameters):
    fields(parameters, {"socket_path"})
    location = path(parameters["socket_path"])
    with opened(str(location)) as (_, checksum):
        bindings = directory(base, "bindings")
        existing = [loads(read(item)) for item in bindings.glob("*.json")]
        for value in existing:
            if value["path"] == str(location) and value["identity"] == checksum:
                return public(value, True)
        if len(existing) >= 64:
            raise Failure("adapter_binding_capacity", "The node provider binding limit is full.")
        value = {"id": secrets.token_hex(16), "path": str(location), "identity": checksum,
                 "label": "Local provider socket: " + location.name}
        write(bindings / (value["id"] + ".json"), value)
        return public(value, True)


@contextmanager
def selected(base, binding_id):
    value = loads(read(directory(base, "bindings") / (identity(binding_id) + ".json")))
    fields(value, {"id", "path", "identity", "label"})
    if value["id"] != binding_id:
        raise Failure("adapter_binding_invalid", "The provider binding identity changed.")
    with opened(value["path"], handoff=True) as (pinned, checksum):
        if value["identity"] != checksum:
            raise Failure("adapter_binding_changed", "The provider socket or process changed. Register a new binding and grant it explicitly.")
        yield pinned


def listing(base):
    results = []
    for item in sorted(directory(base, "bindings").glob("*.json")):
        value = loads(read(item))
        available = False
        try:
            with selected(base, value["id"]):
                available = True
        except (OSError, Failure):
            pass
        results.append(public(value, available))
    if len(results) > 64:
        raise Failure("adapter_binding_invalid", "The provider binding count exceeds its limit.")
    return {"bindings": results}
