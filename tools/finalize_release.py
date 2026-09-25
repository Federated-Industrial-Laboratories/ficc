#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Bind the native Arch artifact to the shared payload and refresh release checksums.
# Inputs: release directory and Arch package. Exit: zero on verified completion.
"""Complete the release set after makepkg has built the Arch package."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

from release_lib.common import digest, write_json


def required_artifacts(version: str) -> set[str]:
    return {f"FICC-{version}-x86_64.AppImage", f"ficc_{version.replace('rc', '~rc')}_amd64.deb",
            f"ficc-{version}-linux-x86_64.tar.gz", f"ficc-{version}-arch-recipe.tar.gz",
            f"ficc-{version}-source.tar.gz", f"ficc-{version}-third-party-sources.tar.gz",
            f"ficc-{version}-py3-none-any.whl", f"ficc-{version}.tar.gz", f"ficc-{version}.cdx.json"}


def verify_original(output: Path, build: dict, arch_name: str) -> None:
    required = required_artifacts(build["version"])
    artifacts = build.get("artifacts", {})
    if not required <= artifacts.keys() or set(artifacts) - required - {arch_name}:
        raise ValueError("Release artifact inventory is incomplete or unexpected")
    for name, checksum in artifacts.items():
        path = output / name
        if path.is_symlink() or not path.is_file() or digest(path) != checksum:
            raise ValueError("Original release artifact is missing or changed: " + name)
    checksums = dict(line.split("  ", 1)[::-1] for line in (output / "SHA256SUMS").read_text().splitlines())
    if checksums != {**artifacts, "build.json": digest(output / "build.json")}:
        raise ValueError("Original release checksums differ from the build receipt")
    actual = {p.name for p in output.iterdir() if p.is_file()}
    if actual - required - {arch_name, "build.json", "SHA256SUMS"}:
        raise ValueError("Release directory contains unexpected artifacts")


def finalize(output: Path, package: Path) -> None:
    build = json.loads((output / "build.json").read_text())
    expected = f"ficc-bin-{build['version']}-1-x86_64.pkg.tar.zst"
    if package.name != expected:
        raise ValueError("Arch package name differs from this release")
    verify_original(output, build, expected)
    process = subprocess.Popen(["zstd", "-dc", str(package)], stdout=subprocess.PIPE)
    found = None
    files, links = {}, {}
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("Unsafe native package member")
                if path.parts[:2] != ("opt", "ficc"):
                    continue
                name = str(path.relative_to("opt/ficc"))
                if name == "bundle.json":
                    if found is not None or not member.isfile() or member.size > 8 * 1024 * 1024:
                        raise ValueError("Invalid Arch payload manifest")
                    stream = archive.extractfile(member)
                    assert stream is not None
                    found = json.load(stream)
                elif member.isfile():
                    stream = archive.extractfile(member)
                    assert stream is not None
                    if name in files:
                        raise ValueError("Duplicate Arch payload member")
                    files[name] = hashlib.file_digest(stream, "sha256").hexdigest()
                elif member.issym():
                    if name in links:
                        raise ValueError("Duplicate Arch payload link")
                    links[name] = member.linkname
                elif not member.isdir():
                    raise ValueError("Unsupported Arch payload member")
        if process.wait() or found != build["payload_manifest"]:
            raise ValueError("Arch package contains a different release payload")
        if files != found["files"] or links != found["links"]:
            raise ValueError("Arch package files differ from the payload manifest")
    finally:
        if process.stdout:
            process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    target = output / package.name
    if package.resolve() != target.resolve():
        shutil.copy2(package, target)
    build["formats_complete"] = True
    build["artifacts"] = {p.name: digest(p) for p in sorted(output.iterdir())
                          if p.is_file() and p.name not in {"build.json", "SHA256SUMS"}}
    write_json(output / "build.json", build)
    (output / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in sorted(output.iterdir())
                                              if p.is_file() and p.name != "SHA256SUMS"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arch-package", type=Path, required=True)
    args = parser.parse_args()
    finalize(args.output, args.arch_package)
    print("All four Linux formats are present and bound to the shared payload.")


if __name__ == "__main__":
    main()
