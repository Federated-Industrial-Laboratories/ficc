# SPDX-License-Identifier: Apache-2.0
"""Download verified build tools and prepare owned installation paths."""

import hashlib
import os
import stat
import tarfile
import tempfile
import urllib.request
from pathlib import Path


def secure_dir(path: Path) -> Path:
    path = path.absolute()
    for item in reversed([path, *path.parents][:-1]):
        if not item.exists() and not item.is_symlink():
            item.mkdir(mode=0o700)
        info = item.lstat()
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()}
                or (info.st_mode & 0o022 and not sticky_root)):
            raise ValueError("Unsafe installation directory: " + str(item))
    if path.stat().st_uid != os.getuid():
        raise ValueError("Installation directory must belong to this account")
    return path


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def download(item: dict, cache: Path) -> Path:
    target = cache / item['name']
    if target.is_symlink():
        raise ValueError("Download cache entry is a link")
    if not target.exists():
        if not item['url'].startswith('https://'):
            raise ValueError("Download requires HTTPS")
        fd, name = tempfile.mkstemp(dir=cache, prefix='.download-')
        try:
            with os.fdopen(fd, 'wb') as out, urllib.request.urlopen(item['url'], timeout=60) as response:
                if not response.url.startswith('https://'):
                    raise ValueError("Download redirect requires HTTPS")
                remaining = item['size'] + 1
                while remaining:
                    block = response.read(min(remaining, 1024 * 1024))
                    if not block:
                        break
                    out.write(block)
                    remaining -= len(block)
            temporary = Path(name)
            if temporary.stat().st_size != item['size'] or sha256(temporary) != item['sha256']:
                raise ValueError("Downloaded input differs from its pinned size or SHA-256")
            os.replace(temporary, target)
        finally:
            Path(name).unlink(missing_ok=True)
    if not target.is_file() or target.stat().st_size != item['size'] or sha256(target) != item['sha256']:
        raise ValueError("Cached input differs from its pinned size or SHA-256")
    return target


def unpack(path: Path, destination: Path) -> None:
    if not hasattr(tarfile, 'data_filter'):
        raise ValueError("Update system Python to a security-maintained version with tar extraction filters")
    destination.mkdir()
    with tarfile.open(path) as archive:
        archive.extractall(destination, filter='data')
