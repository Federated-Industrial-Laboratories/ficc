# SPDX-License-Identifier: Apache-2.0
"""Verify a disposable installed wheel and detect a changed file before importing its code."""

import argparse
import importlib.metadata
import json
import os
import subprocess
import sys
from pathlib import Path

from ficc.execution.providers import distribution


def check(target):
    if target.exists():
        raise ValueError("Use a new disposable package directory.")
    target.mkdir(mode=0o700)
    return target


def installed(target):
    sys.path.insert(0, str(target))
    importlib.invalidate_caches()
    entry, before = distribution("podman", owner=os.getuid())
    barrier = Path(entry.dist.locate_file("ficc_executor_podman/barrier"))
    headers = subprocess.run(["readelf", "-l", str(barrier)], capture_output=True, text=True, check=True).stdout
    if "INTERP" in headers:
        raise ValueError("The trusted executable barrier has a dynamic interpreter.")
    source = Path(entry.dist.locate_file("ficc_executor_podman/__init__.py"))
    source.write_bytes(source.read_bytes() + b"\n# Modified disposable package input.\n")
    try:
        distribution("podman", owner=os.getuid())
    except ValueError:
        return {"verified_digest": before, "static_barrier": True, "modified_file_refused_before_import": True,
                "ownership_scope": "ordinary-user disposable install; production requires root"}
    raise ValueError("The modified installed provider was accepted.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    check(args.target)
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--no-compile",
                    "--target", str(args.target), str(args.wheel)], check=True, umask=0o022)
    print(json.dumps(installed(args.target), indent=2))
