# SPDX-License-Identifier: Apache-2.0
"""Validate release inputs and write bounded, reproducible archives."""

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command: list[str], *, cwd: Path | None = None, env: dict | None = None) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fetch(lock: dict, cache: Path) -> dict[str, Path]:
    cache.mkdir(parents=True, exist_ok=True)
    result = {}
    for item in lock["inputs"]:
        name = item["name"]
        if Path(name).name != name or not 0 < item["size"] <= 100 * 1024 * 1024:
            raise ValueError("Invalid release input metadata")
        target = cache / name
        if target.exists() and (target.stat().st_size != item["size"] or digest(target) != item["sha256"]):
            raise ValueError("Cached input differs from its pinned hash: " + name)
        if not target.exists():
            url = urlsplit(item["url"])
            if url.scheme != "https" or url.hostname not in {
                "github.com", "raw.githubusercontent.com", "ftp.osuosl.org", "git.musl-libc.org",
            } or url.username or url.password:
                raise ValueError("Release inputs must use the pinned HTTPS source")
            fd, temporary = tempfile.mkstemp(dir=cache, prefix=".download-")
            try:
                with os.fdopen(fd, "wb") as output, urllib.request.urlopen(item["url"], timeout=60) as response:
                    remaining = item["size"] + 1
                    while remaining:
                        block = response.read(min(1024 * 1024, remaining))
                        if not block:
                            break
                        output.write(block)
                        remaining -= len(block)
                candidate = Path(temporary)
                if candidate.stat().st_size != item["size"] or digest(candidate) != item["sha256"]:
                    raise ValueError("Downloaded input differs from its pinned hash: " + name)
                candidate.replace(target)
            finally:
                Path(temporary).unlink(missing_ok=True)
        result[item["id"]] = target
    return result


def unpack(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        if len(members) > 50000 or sum(m.size for m in members) > 1024 * 1024 * 1024:
            raise ValueError("Archive exceeds the release input limit")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError("Unsafe archive member: " + member.name)
        bundle.extractall(destination, members=members, filter="data")


def archive_tree(source: Path, output: Path, epoch: int) -> None:
    import gzip

    with output.open("wb") as target, gzip.GzipFile(filename="", fileobj=target, mode="wb", mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for path in [source, *sorted(source.rglob("*"))]:
                if path.is_symlink():
                    resolved = path.resolve()
                    if not resolved.is_relative_to(source.resolve()):
                        raise ValueError("Archive link escapes the payload")
                info = archive.gettarinfo(str(path), arcname=str(path.relative_to(source.parent)))
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = epoch
                info.mode = 0o755 if info.isdir() or info.mode & 0o111 else 0o644
                if info.issym():
                    info.mode = 0o777
                if info.isfile():
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
                else:
                    archive.addfile(info)


def normalize_tree(root: Path, epoch: int) -> None:
    """Remove local creation times from every file, link and directory."""
    for path in [*root.rglob("*"), root]:
        os.utime(path, (epoch, epoch), follow_symlinks=False)


def normalize_sdist(path: Path, work: Path, epoch: int) -> None:
    """Replace generated owner names, IDs and timestamps with public metadata."""
    destination = work / "sdist-normalized"
    unpack(path, destination)
    roots = list(destination.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError("Source distribution must have one root directory")
    archive_tree(roots[0], path, epoch)


def snapshot(root: Path, destination: Path, allow_dirty: bool) -> dict:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    if not (root / ".git").exists():
        provenance = json.loads((root / "release-source.json").read_text())
        if provenance["dirty"] and not allow_dirty:
            raise ValueError("This source archive is a qualification candidate")
        destination.mkdir(parents=True)
        for name, checksum in provenance["files"].items():
            path = PurePosixPath(name)
            source = root / path
            if path.is_absolute() or ".." in path.parts or source.is_symlink() or not source.is_file():
                raise ValueError("Invalid source archive member")
            if not source.resolve().is_relative_to(root.resolve()) or digest(source) != checksum:
                raise ValueError("Source archive content differs from its manifest: " + name)
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
        return provenance
    dirty = bool(git("status", "--porcelain"))
    if dirty and not allow_dirty:
        raise ValueError("Commit the source before a release build, or use --allow-dirty for qualification")
    files = git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0")
    destination.mkdir(parents=True)
    manifest = {}
    for name in sorted(set(files)):
        if not name:
            continue
        source = root / name
        if source.is_symlink() or not source.is_file():
            raise ValueError("Release source must contain regular tracked files: " + name)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
        manifest[name] = digest(source)
    return {"commit": git("rev-parse", "HEAD"), "dirty": dirty,
            "epoch": int(git("show", "-s", "--format=%ct", "HEAD")), "files": manifest}
