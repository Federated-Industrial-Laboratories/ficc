# SPDX-License-Identifier: Apache-2.0
"""Inspect and pre-stage verified project objects while the installed executor is stopped."""
import os
import re
import secrets
import stat
from pathlib import Path

from pydantic import TypeAdapter

from .ledger import Ledger
from .model_cache import ModelCache
from .process import properties
from .spec import Digest, Identity, ObjectReference


def rows(cache):
    values = []
    for path in cache.root.glob("*.blob"):
        match = re.fullmatch(r"([0-9a-f]{32})-([0-9a-f]{64})\.blob", path.name)
        info = path.lstat()
        if not match or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o222:
            raise ValueError("A node model cache object has an invalid identity.")
        values.append({"project": match[1], "digest": "sha256:" + match[2], "bytes": info.st_size})
    return values


def operate(settings, action, *, project=None, digest=None, source=None, size=None):
    if os.geteuid() != 0 or settings.model_cache is None:
        raise ValueError("Node cache administration requires root and an explicitly configured model cache.")
    current = properties(settings.service, ("ActiveState", "MainPID"))
    if current.get("ActiveState") not in {"inactive", "failed"} or current.get("MainPID") != "0":
        raise ValueError("Stop the installed supervisor before administering its model cache.")
    ledger = Ledger(Path(settings.state), settings.installation_id)
    cache = None
    try:
        if any(row["state"] != "released" for row in ledger.all()):
            raise ValueError("Release every retained attempt before administering the node model cache.")
        cache = ModelCache(settings.model_cache, ledger.retained)
        entries = rows(cache)
        if action == "list":
            return {"objects": entries, "used_bytes": sum(row["bytes"] for row in entries),
                    "maximum_bytes": settings.model_cache.maximum_bytes, "filesystem_uuid": settings.model_cache.filesystem_uuid}
        project = TypeAdapter(Identity).validate_python(project)
        digest = TypeAdapter(Digest).validate_python(digest)
        target = cache.root / (project + "-" + digest.removeprefix("sha256:") + ".blob")
        if action == "evict":
            target.unlink(missing_ok=True)
            sync(cache)
            return {"project": project, "digest": digest, "removed": True}
        item = ObjectReference(id=secrets.token_hex(16), name="model.bin", digest=digest, bytes=size).model_dump()
        if target.exists():
            if target.stat().st_size != size:
                raise ValueError("The retained digest has a different declared byte count.")
            return {"project": project, "digest": digest, "bytes": size, "cached": True}
        if (len(entries) >= settings.model_cache.maximum_files
                or sum(row["bytes"] for row in entries) + size > settings.model_cache.maximum_bytes):
            raise ValueError("The node cache is full. Evict an unneeded object before import.")
        source = Path(source)
        temporary = cache.root / (secrets.token_hex(16) + ".partial")
        def check():
            info = cache.root.lstat()
            if (info.st_dev, info.st_ino) != cache.binding:
                raise ValueError("The configured model cache directory changed during import.")
        try:
            cache.copy(source, temporary, item, check, 0, source.lstat().st_uid)
            cache.verify()
            os.replace(temporary, target)
            sync(cache)
        finally:
            temporary.unlink(missing_ok=True)
        return {"project": project, "digest": digest, "bytes": size, "verified": True}
    finally:
        if cache:
            cache.close()
        ledger.close()


def sync(cache):
    fd = os.open(cache.root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
