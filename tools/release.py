#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Build pinned Linux artifacts; output a source-bound manifest and checksums.
# Inputs: Git source and verified cache. Exit: zero on a complete build.
"""Build the x86_64 Linux release formats outside the source tree."""

import argparse
import json
import os
import platform
import shutil
import tomllib
from pathlib import Path

from release_lib import formats, notices, payload
from release_lib.common import archive_tree, digest, fetch, snapshot, write_json


def main() -> None:
    os.umask(0o022)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true", help="Build a marked qualification candidate")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("This release target requires Linux x86_64")
    source, work, output, cache = [p.resolve() for p in (args.source, args.work, args.output, args.cache)]
    if any(p == source or p.is_relative_to(source) for p in (work, output, cache)):
        raise ValueError("Build work, output and downloads must stay outside the source tree")
    if work.exists() or output.exists():
        raise ValueError("Use new work and output directories for each build")
    if work == output or work.is_relative_to(output) or output.is_relative_to(work):
        raise ValueError("Build work and output must be separate directories")
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    provenance = snapshot(source, work / "source", args.allow_dirty)
    source = work / "source"
    lock = json.loads((source / "packaging/inputs.json").read_text())
    inputs = fetch(lock, cache)
    version = tomllib.loads((source / "pyproject.toml").read_text())["project"]["version"]
    source_archive = work / f"ficc-{version}-source"
    shutil.copytree(source, source_archive)
    write_json(source_archive / "release-source.json", provenance)
    archive_tree(source_archive, output / (source_archive.name + ".tar.gz"), provenance["epoch"])
    notices.sources(inputs, lock, work, output, version, provenance["epoch"])
    tree, version = payload.build(source, work, inputs, provenance, lock)
    epoch = provenance["epoch"]
    portable = output / (tree.name + ".tar.gz")
    archive_tree(tree, portable, epoch)
    formats.deb(tree, work, output, version, epoch)
    formats.appimage(tree, source, work, output, inputs, version, epoch)
    formats.arch_recipe(tree, portable, output, version, epoch)
    shutil.copy2(tree / "sbom.cdx.json", output / f"ficc-{version}.cdx.json")
    for item in (source / "dist").iterdir():
        shutil.copy2(item, output / item.name)
    write_json(output / "build.json", {"version": version, "architecture": "x86_64", "source": provenance,
                                      "inputs": lock, "payload_manifest": json.loads((tree / "bundle.json").read_text()),
                                      "artifacts": {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()}})
    (output / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in sorted(output.iterdir()) if p.is_file()))
    print("Release formats built. Build the Arch recipe with makepkg before publication.")


if __name__ == "__main__":
    main()
