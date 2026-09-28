#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build deterministic module ZIP files and inspect them with the host validator."""

import argparse
import hashlib
import importlib.util
import io
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Use the validator from this source tree, without an installed service.
from ficc.errors import Failure  # noqa: E402
from ficc.modules.archive import MAX_EXPANDED, MAX_FILE, MAX_MANIFEST, inspect_archive  # noqa: E402
from ficc.modules.manifest import package_path  # noqa: E402
from ficc.modules.validation import dumps, loads  # noqa: E402


def read_source(source: Path) -> tuple[dict, dict[str, bytes]]:
    """Read a manifest and the explicit payload directory without following links."""
    if source.is_symlink() or not source.is_dir():
        raise ValueError("The source directory must be a real directory.")
    manifest_file = source / "manifest.json"
    manifest = loads(read_file(manifest_file, MAX_MANIFEST), MAX_MANIFEST)
    files = {}
    payload = source / "payload"
    if payload.is_symlink():
        raise ValueError("The payload directory must not be a link.")
    if payload.exists():
        if not payload.is_dir():
            raise ValueError("The payload must be a directory.")
        for directory, directories, names in os.walk(payload, followlinks=False):
            if any((Path(directory) / name).is_symlink() for name in directories):
                raise ValueError("The payload contains a directory link.")
            for name in sorted(names):
                path = Path(directory) / name
                relative = package_path(path.relative_to(payload).as_posix())
                if relative.casefold() == "manifest.json":
                    raise ValueError("The payload uses the reserved manifest name.")
                files[relative] = read_file(path, MAX_FILE)
                if len(files) > 253 or sum(map(len, files.values())) > MAX_EXPANDED:
                    raise ValueError("The payload exceeds the package limit.")
    return manifest, files


def read_file(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise ValueError("The source file is not regular, is linked, or exceeds the limit.")
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("The source file exceeds the limit.")
        return data


def build_archive(manifest: dict, files: dict[str, bytes]) -> bytes:
    """Use fixed ZIP metadata and a complete SHA256 inventory for stable bytes."""
    manifest = dict(manifest)
    manifest["files"] = {name: hashlib.sha256(data).hexdigest()
                         for name, data in sorted(files.items())}
    members = {"manifest.json": dumps(manifest), **files}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(members.items()):
            package_path(name)
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, data)
    data = output.getvalue()
    inspect_archive(data)
    return data


def publish(manifest: dict, files: dict[str, bytes], output: Path) -> Path:
    files = dict(files)
    files.setdefault("licenses/FICC-Apache-2.0.txt", (ROOT / "LICENSE").read_bytes())
    files.setdefault("licenses/FICC-NOTICE.txt", (ROOT / "NOTICE").read_bytes())
    data = build_archive(manifest, files)
    name = f"{manifest['id']}-{manifest['version']}.ficc-module.zip"
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ValueError("The output directory must not be a link.")
    destination = output / name
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or destination.read_bytes() != data:
            raise ValueError("The output exists with different bytes. Use a new version or directory.")
    else:
        fd, temporary = tempfile.mkstemp(prefix=".module-", dir=output)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
    print(f"{hashlib.sha256(data).hexdigest()}  {destination}")
    return destination


def native_payload(source: Path, manifest: dict, files: dict[str, bytes], cache: Path,
                   fetch: bool) -> dict[str, bytes]:
    """Compile a declared native payload before archive creation."""
    if manifest["runtime"]["kind"] != "native" or not (source / "build.json").exists():
        return files
    spec = importlib.util.spec_from_file_location("module_native_build", ROOT / "tools/module_native_build.py")
    assert spec and spec.loader
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    generated = builder.build(source, manifest, cache, fetch)
    if set(generated) & set(files):
        raise ValueError("A generated native payload repeats an existing package member.")
    return {**files, **generated}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    defaults = commands.add_parser("defaults", help="Build the supplied runtime packages")
    defaults.add_argument("--output", type=Path, default=ROOT / "dist/modules")
    pack = commands.add_parser("pack", help="Build one manifest.json and payload directory")
    pack.add_argument("source", type=Path)
    pack.add_argument("--output", type=Path, default=ROOT / "dist/modules")
    for command in (defaults, pack):
        command.add_argument("--cache", type=Path, default=ROOT / "sdk/build")
        command.add_argument("--fetch", action="store_true", help="Fetch pinned native build dependencies")
    examples = commands.add_parser("examples", help="Build the six language examples")
    examples.add_argument("--output", type=Path, default=ROOT / "dist/module-examples")
    examples.add_argument("--cache", type=Path, default=ROOT / "sdk/build")
    examples.add_argument("--fetch", action="store_true", help="Fetch pinned build dependencies")
    examples.add_argument("--broker", action="store_true", help="Build protocol-two resource examples")
    examples.add_argument("--node", default="node", help="Node.js executable for TypeScript")
    examples.add_argument("--language", choices=["c", "cpp", "rust", "python", "javascript", "typescript"])
    args = parser.parse_args()
    if args.command == "pack":
        manifest, files = read_source(args.source)
        publish(manifest, native_payload(args.source, manifest, files, args.cache, args.fetch), args.output)
    elif args.command == "defaults":
        supplied = []
        sources = sorted(path.parent for path in (ROOT / "modules").glob("*/manifest.json"))
        if not sources:
            raise ValueError("No supplied module manifests were found.")
        for source in sources:
            manifest, files = read_source(source)
            files = native_payload(source, manifest, files, args.cache, args.fetch)
            if manifest["runtime"]["kind"] == "python":
                files["ficc_module.py"] = read_file(ROOT / "sdk/python/ficc_module.py", MAX_FILE)
                if manifest.get("role") == "provider-adapter":
                    files["ficc_adapter.py"] = read_file(ROOT / "sdk/python/ficc_adapter.py", MAX_FILE)
            archive = publish(manifest, files, args.output)
            supplied.append({"id": manifest["id"], "version": manifest["version"],
                             "display_name": manifest.get("display_name", manifest["id"]),
                             "filename": archive.name, "digest": hashlib.sha256(archive.read_bytes()).hexdigest()})
        index, data = args.output / "index.json", dumps({"version": 1, "modules": supplied})
        try:
            with index.open("xb") as stream:
                stream.write(data)
        except FileExistsError:
            if read_file(index, 65536) != data:
                raise ValueError("The module index changed. Use a new output directory.") from None
    else:
        spec = importlib.util.spec_from_file_location("module_sdk_build", ROOT / "sdk/build.py")
        assert spec and spec.loader
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        for language in [args.language] if args.language else builder.LANGUAGES:
            publish(*builder.example(language, args.cache, args.fetch, args.node, broker=args.broker), args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, Failure, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
