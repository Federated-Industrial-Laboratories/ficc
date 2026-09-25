# SPDX-License-Identifier: Apache-2.0
"""Install a verified private runtime so the user service does not need FUSE."""

import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from pathlib import Path

from .settings import private_directory


def verify(root: Path, manifest: dict) -> None:
    files = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and not p.is_symlink()}
    links = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_symlink()}
    if files != set(manifest["files"]) | {"bundle.json"} or links != set(manifest["links"]):
        raise ValueError("The bundled runtime inventory is incomplete or changed.")
    for name, checksum in manifest["files"].items():
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("The bundled runtime contains an external path.")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
                raise ValueError("The bundled runtime content changed.")
    for name, target in manifest["links"].items():
        path = root / name
        if os.readlink(path) != target or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("The bundled runtime contains an external link.")


def install(source: Path) -> Path:
    data = (source / "bundle.json").read_bytes()
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("The runtime inventory exceeds the size limit.")
    manifest = json.loads(data)
    identity = hashlib.sha256(data).hexdigest()
    data_root = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))).absolute()
    root = data_root / "ficc/runtimes"
    private_directory(root.parent)
    private_directory(root)
    fd = os.open(root / "install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("The runtime installation lock is not private.")
        deadline = time.monotonic() + 35
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError("Another runtime installation is busy.") from None
                time.sleep(0.1)
        target = root / identity
        if target.exists() or target.is_symlink():
            private_directory(target)
            if (target / "bundle.json").read_bytes() != data:
                raise ValueError("The saved runtime inventory changed.")
            verify(target, manifest)
        else:
            verify(source, manifest)
            with tempfile.TemporaryDirectory(prefix=".install-", dir=root) as temporary:
                candidate = Path(temporary) / "runtime"
                shutil.copytree(source, candidate, symlinks=True)
                candidate.chmod(0o700)
                verify(candidate, manifest)
                candidate.rename(target)
        command = target / "python/bin/ficc"
        if not command.is_file() or not os.access(command, os.X_OK):
            raise ValueError("The installed runtime command is missing.")
        return command
    finally:
        os.close(fd)
