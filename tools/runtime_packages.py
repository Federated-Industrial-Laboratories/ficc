# SPDX-License-Identifier: Apache-2.0
"""Build runtime wheels; optionally install locked dependencies and wheels after the host.

Inputs: trusted source, a new output directory and the active Python environment.
Output: wheels and inventory. Exit: zero on success; nonzero on a failed build.
"""

import argparse
import configparser
import email.parser
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath


def catalog(source):
    source = Path(source).resolve()
    value = json.loads((source / "packaging/providers.json").read_text())
    if set(value) != {"version", "dependency_locks", "packages"} or value["version"] != 1:
        raise ValueError("The runtime package catalogue is invalid.")
    for key in ("dependency_locks", "packages"):
        if not isinstance(value[key], list) or len(value[key]) != len(set(value[key])) or len(value[key]) > 64:
            raise ValueError("The runtime package catalogue repeats or exceeds its entries.")
        for name in value[key]:
            path = PurePosixPath(name)
            if path.is_absolute() or str(path) != name or ".." in path.parts or not (source / name).resolve().is_relative_to(source):
                raise ValueError("A runtime package path escapes the source.")
            if not (source / name).exists():
                raise ValueError("A declared runtime package input is missing: " + name)
    return value


def locks(source):
    return [str(Path(source) / name) for name in catalog(source)["dependency_locks"]]


def metadata(wheel):
    with zipfile.ZipFile(wheel) as archive:
        manifests = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(manifests) != 1:
            raise ValueError("A runtime wheel must contain one distribution metadata record.")
        value = email.parser.BytesParser().parsebytes(archive.read(manifests[0]))
        entries = configparser.ConfigParser(interpolation=None)
        path = manifests[0].removesuffix("METADATA") + "entry_points.txt"
        if path in archive.namelist():
            entries.read_string(archive.read(path).decode())
    if not value["Name"] or not value["Version"]:
        raise ValueError("Runtime package name and version are required.")
    return {"name": value["Name"], "version": value["Version"],
            "entry_points": {group: dict(entries[group]) for group in entries.sections()}}


def build(source, destination, python, *, env=None):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError("Build runtime wheels in a new output directory.")
    destination.mkdir(parents=True)
    packages, names = [], set()
    for path in catalog(source)["packages"]:
        before = set(destination.glob("*.whl"))
        subprocess.run([str(python), "-m", "build", "--wheel", "--no-isolation", "--outdir", str(destination),
                        str(source / path)], env=env, check=True)
        created = set(destination.glob("*.whl")) - before
        if len(created) != 1:
            raise ValueError("Each runtime package must produce exactly one wheel.")
        wheel = created.pop()
        package = metadata(wheel)
        if package["name"] in names:
            raise ValueError("Runtime distribution names must be distinct.")
        names.add(package["name"])
        packages.append({**package, "file": wheel.name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()})
    (destination / "index.json").write_text(json.dumps({"version": 1, "packages": packages}, indent=2, sort_keys=True) + "\n")
    return packages


def install(python, directory, packages, *, env=None):
    wheels = []
    for item in packages:
        name = item["file"]
        if Path(name).name != name or not name.endswith(".whl"):
            raise ValueError("The runtime wheel name is invalid.")
        wheel = Path(directory) / name
        if wheel.is_symlink() or hashlib.sha256(wheel.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("The runtime wheel differs from its build inventory.")
        wheels.append(str(wheel))
    subprocess.run([str(python), "-I", "-m", "pip", "install", "--no-compile", "--no-deps", "--no-index", *wheels], env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--install", action="store_true", help="Install trusted providers into the active host environment.")
    args = parser.parse_args()
    if args.install:
        options = [argument for path in locks(args.source) for argument in ("-r", path)]
        subprocess.run([sys.executable, "-m", "pip", "install", "--require-hashes", *options], check=True)
    packages = build(args.source, args.output, sys.executable)
    if args.install:
        install(sys.executable, args.output, packages)
    print(json.dumps({"packages": len(packages), "installed": args.install}))


if __name__ == "__main__":
    main()
