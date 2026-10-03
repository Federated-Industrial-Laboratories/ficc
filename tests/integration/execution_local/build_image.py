# SPDX-License-Identifier: Apache-2.0
"""Build the small static CPU qualification image without a registry or container engine."""

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def member(archive, name, data=b"", mode=0o644, directory=False):
    entry = tarfile.TarInfo(name)
    entry.mode, entry.uid, entry.gid, entry.mtime = mode, 0, 0, 0
    if directory:
        entry.type = tarfile.DIRTYPE
        archive.addfile(entry)
    else:
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))


def build(output):
    output.mkdir(mode=0o700)
    source = Path(__file__).with_name("fixture.c")
    argv = ["cc", "-static", "-Os", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong",
            "-Wl,--build-id=none", str(source), "-o", str(output / "fixture")]
    subprocess.run(argv, check=True)
    files = {"fixture": (output / "fixture").read_bytes(), "ficc/barrier": b"",
             "etc/passwd": b"root:x:0:0:work:/:/fixture\n", "etc/group": b"root:x:0:\n",
             "etc/hostname": b"", "etc/resolv.conf": b""}
    directories = ("dev", "dev/pts", "proc", "sys", "run", "work", "inputs", "tmp", "etc", "ficc", "ficc/control")
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in directories:
            member(archive, name, mode=0o755, directory=True)
        for name, data in sorted(files.items()):
            member(archive, name, data, mode=0o755 if name == "fixture" else 0o644)
    data = layer.getvalue()
    config = encoded({"architecture": "amd64", "os": "linux", "config": {
        "User": "0:0", "Entrypoint": ["/fixture"], "Env": ["PATH=/", "LANG=C"], "WorkingDir": "/work"},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + digest(data)]}})
    manifest = encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + digest(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:" + digest(data), "size": len(data)}]})
    index = encoded({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": "sha256:" + digest(manifest), "size": len(manifest),
        "annotations": {"org.opencontainers.image.ref.name": "localhost/ficc-execution-fixture:1"}}]})
    image = output / "image.oci.tar"
    with tarfile.open(image, "w", format=tarfile.USTAR_FORMAT) as archive:
        member(archive, "oci-layout", encoded({"imageLayoutVersion": "1.0.0"}))
        member(archive, "index.json", index)
        for content in (config, manifest, data):
            member(archive, "blobs/sha256/" + digest(content), content)
    value = {"image_digest": "sha256:" + digest(config), "archive_digest": "sha256:" + digest(image.read_bytes()),
             "archive_bytes": image.stat().st_size, "build_argv": argv, "source_digest": "sha256:" + digest(source.read_bytes())}
    (output / "build.json").write_text(json.dumps(value, indent=2) + "\n")
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New build directory; existing paths are refused.")
    print(json.dumps(build(parser.parse_args().output), indent=2))
