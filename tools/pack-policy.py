#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Build a signed runtime policy archive. Inputs: source, publisher, key. Output: ZIP. Exit: zero on success.

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ficc.policy_packages import (  # noqa: E402
    MAX_ARCHIVE,
    NAMESPACE,
    inspect,
    manifest,
    payload_path,
)


def build(source, publisher, key, output):
    value = json.loads((source / "package.json").read_text())
    root = source / "payload"
    payload = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Policy source paths must not be symbolic links.")
        if path.is_file():
            name = payload_path(path.relative_to(root).as_posix())
            payload[name] = path.read_bytes()
    value.update(publisher=publisher, files={name: hashlib.sha256(data).hexdigest() for name, data in payload.items()})
    signed = (json.dumps(manifest(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    with tempfile.TemporaryDirectory(prefix="ficc-policy-sign-") as temporary:
        path = Path(temporary) / "manifest.json"
        path.write_bytes(signed)
        result = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(key.resolve()), "-n", NAMESPACE, str(path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
        if result.returncode:
            raise ValueError("Policy signing failed. Check the signing key and its access requirements.")
        signature = path.with_suffix(".json.sig").read_bytes()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in {"manifest.json": signed, "manifest.sig": signature,
                           **{"payload/" + name: data for name, data in payload.items()}}.items():
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o100600 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    raw = buffer.getvalue()
    inspect(raw)
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("The policy archive exceeds its size limit.")
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    return {"archive": str(output), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def main():
    parser = argparse.ArgumentParser(description="Sign a policy package with an explicitly selected OpenSSH key.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.source, args.publisher, args.key, args.output)))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
