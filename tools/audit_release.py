#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Scan expanded release contents for private identifiers from an external deny list.
# Inputs: directories, archives and private JSON markers. Exit: zero for no matches.
"""Audit known private identifiers without placing the identifiers in release source."""

import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path


def runtime_input() -> dict:
    lock = json.loads((Path(__file__).resolve().parents[1] / "packaging/inputs.json").read_text())
    return next(i for i in lock["inputs"] if i["id"] == "runtime")


class Audit:
    def __init__(self, markers: list[str], sources: dict[str, str] | None = None):
        if not markers or any(not isinstance(m, str) or len(m) < 4 for m in markers):
            raise ValueError("Supply a nonempty private list of specific identifiers")
        self.markers = [re.compile(rb"(?<![A-Za-z0-9_.-])" + re.escape(m.encode()) + rb"(?![A-Za-z0-9_.-])", re.I)
                        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", m) else re.compile(re.escape(m.encode()))
                        for m in markers]
        self.files = 0
        self.bytes = 0
        self.findings: list[str] = []
        self.sources = sources or {}
        self.verified_sources: list[str] = []

    def scan(self, name: str, data: bytes) -> None:
        encoded = name.encode("utf-8", "surrogateescape")
        if any(m.search(data) or m.search(encoded) for m in self.markers):
            self.findings.append(name)

    def data(self, name: str, data: bytes, depth: int = 0) -> None:
        if depth > 5 or len(data) > 256 * 1024 * 1024:
            raise ValueError("Release audit member exceeds its bound: " + name)
        self.files += 1
        self.bytes += len(data)
        self.scan(name, data)
        basename = Path(name.split("!")[-1]).name
        if basename in self.sources:
            if hashlib.sha256(data).hexdigest() != self.sources[basename]:
                raise ValueError("Upstream source archive differs from its pinned input")
            self.verified_sources.append(name)
            return
        stream = io.BytesIO(data)
        if name.endswith((".deb", ".pkg.tar.zst", ".AppImage")):
            with tempfile.TemporaryDirectory(prefix="ficc-member-audit-") as temporary:
                member = Path(temporary) / basename
                member.write_bytes(data)
                self.path(member, name, depth)
        elif name.endswith((".whl", ".zip")):
            with zipfile.ZipFile(stream) as archive:
                self.scan(name + "!zip-metadata", archive.comment)
                for item in archive.infolist():
                    if item.file_size > 256 * 1024 * 1024:
                        raise ValueError("Oversized ZIP member")
                    if not item.is_dir():
                        self.scan(name + "!" + item.filename + "!metadata", item.comment + item.extra)
                        self.data(name + "!" + item.filename, archive.read(item), depth + 1)
        elif name.endswith((".tar.gz", ".tar.xz", ".tar")):
            with tarfile.open(fileobj=stream) as archive:
                self.tar(name, archive, depth)

    def tar(self, name: str, archive: tarfile.TarFile, depth: int = 0) -> None:
        self.scan(name + "!tar-metadata", json.dumps(archive.pax_headers).encode())
        for item in archive:
            if item.size > 256 * 1024 * 1024:
                raise ValueError("Oversized tar member")
            self.scan(name + "!" + item.name + "!metadata", json.dumps({
                "uname": item.uname, "gname": item.gname, "uid": item.uid, "gid": item.gid,
                "pax": item.pax_headers, "link": item.linkname,
            }).encode())
            if item.isfile():
                stream = archive.extractfile(item)
                assert stream is not None
                self.data(name + "!" + item.name, stream.read(), depth + 1)
            elif item.issym() or item.islnk():
                self.data(name + "!" + item.name, item.linkname.encode(), depth + 1)

    def path(self, path: Path, label: str | None = None, depth: int = 0) -> None:
        if depth > 5:
            raise ValueError("Release audit nesting exceeds its bound")
        name = label or path.name
        if path.is_dir():
            for item in sorted(path.rglob("*")):
                member = name + "!" + str(item.relative_to(path))
                if item.is_symlink():
                    self.data(member, str(item.readlink()).encode(), depth)
                elif item.is_file():
                    self.path(item, member, depth)
                else:
                    self.scan(member, b"")
        elif path.suffix == ".deb" or path.name.endswith(".pkg.tar.zst"):
            commands = ([("data", ["dpkg-deb", "--fsys-tarfile", str(path)]),
                         ("control", ["dpkg-deb", "--ctrl-tarfile", str(path)])] if path.suffix == ".deb"
                        else [("data", ["zstd", "-dc", str(path)])])
            for section, command in commands:
                process = subprocess.Popen(command, stdout=subprocess.PIPE)
                try:
                    with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                        self.tar(name + "!" + section, archive, depth)
                    if process.wait():
                        raise ValueError("Cannot expand native package")
                finally:
                    if process.stdout:
                        process.stdout.close()
                    if process.poll() is None:
                        process.kill()
                        process.wait()
        elif path.suffix == ".AppImage":
            # Locate the known runtime boundary without executing the image.
            runtime = runtime_input()
            with path.open("rb") as stream:
                prefix = stream.read(runtime["size"])
            normalized = bytearray(prefix)
            offset = runtime["digest_md5_offset"]
            if not 0 <= offset <= len(prefix) - 16:
                raise ValueError("Invalid AppImage digest section")
            normalized[offset:offset + 16] = bytes(16)
            if hashlib.sha256(normalized).hexdigest() != runtime["sha256"]:
                raise ValueError("AppImage runtime differs from the release lock")
            self.data(name + "!runtime", prefix, depth)
            with tempfile.TemporaryDirectory(prefix="ficc-image-audit-") as temporary:
                target = Path(temporary) / "image"
                subprocess.run(["unsquashfs", "-no-progress", "-processors", "2", "-offset", str(runtime["size"]),
                                "-dest", str(target), str(path)], check=True, stdout=subprocess.DEVNULL)
                self.path(target, name + "!image", depth + 1)
        else:
            self.data(name, path.read_bytes(), depth)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deny-file", required=True, type=Path, help="Private JSON string array outside the release")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    lock = json.loads((Path(__file__).resolve().parents[1] / "packaging/inputs.json").read_text())
    sources = {i["name"]: i["sha256"] for i in lock["inputs"] if i["id"].endswith("-source")}
    audit = Audit(json.loads(args.deny_file.read_text()), sources)
    for path in args.paths:
        audit.path(path)
    if not audit.files:
        raise ValueError("No release content was inspected")
    print(json.dumps({"members": audit.files, "bytes": audit.bytes, "findings": audit.findings,
                      "unmodified_upstream_source_archives": audit.verified_sources}, indent=2))
    raise SystemExit(bool(audit.findings))


if __name__ == "__main__":
    main()
