#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Sign or verify a completed release checksum file with an explicitly trusted OpenSSH key.
# Inputs: release directory and key paths. Output: public signature files; exit: zero on success.
"""Use SSHSIG to authenticate release checksums against an independently trusted Ed25519 key."""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ficc.policy_packages import public_key  # noqa: E402

NAMESPACE = "ficc-release-v1"
FILES = {"RELEASE.pub", "SHA256SUMS.sig"}


def read(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("A release signature input is missing, linked or too large.")
    raw = path.read_bytes()
    if not raw or len(raw) > limit:
        raise ValueError("A release signature input is empty or too large.")
    return raw


def trusted_public(path):
    return public_key(read(path, 1024).decode("ascii"))


def verify(output, trusted_key):
    expected, fingerprint = trusted_public(trusted_key)
    supplied, _ = trusted_public(output / "RELEASE.pub")
    if supplied != expected:
        raise ValueError("The release publisher differs from the independently trusted key.")
    manifest = read(output / "SHA256SUMS", 131072)
    signature = read(output / "SHA256SUMS.sig", 16384)
    with tempfile.TemporaryDirectory(prefix="ficc-release-verify-") as temporary:
        root = Path(temporary)
        (root / "signers").write_text(f'ficc-release namespaces="{NAMESPACE}" {expected}\n')
        (root / "signature").write_bytes(signature)
        result = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(root / "signers"),
                                 "-I", "ficc-release", "-n", NAMESPACE, "-s", str(root / "signature")],
                                input=manifest, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30, check=False)
    if result.returncode:
        raise ValueError("The release checksum signature is invalid for the trusted publisher.")
    return fingerprint


def sign(output, key, trusted_key):
    from publish_release import validate

    validate(output)
    if any((output / name).exists() or (output / name).is_symlink() for name in FILES):
        raise ValueError("This release already contains signature files; verify them instead.")
    public, _ = trusted_public(trusted_key)
    with tempfile.TemporaryDirectory(prefix="ficc-release-sign-") as temporary:
        root = Path(temporary)
        path = root / "SHA256SUMS"
        path.write_bytes(read(output / "SHA256SUMS", 131072))
        (root / "RELEASE.pub").write_text(public + "\n")
        result = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(key.resolve()),
                                 "-n", NAMESPACE, str(path)], timeout=120, check=False)
        if result.returncode:
            raise ValueError("Release signing failed; check the explicitly selected key and its access.")
        fingerprint = verify(root, trusted_key)
        if path.read_bytes() != read(output / "SHA256SUMS", 131072):
            raise ValueError("Release checksums changed during signing.")
        for name in sorted(FILES):
            with (output / name).open("xb") as target:
                target.write((root / name).read_bytes())
    verify(output, trusted_key)
    return fingerprint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("sign", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True,
                        help="Publisher public key obtained through an independent trusted channel.")
    parser.add_argument("--key", type=Path, help="Explicit signing key, used only by sign.")
    args = parser.parse_args()
    if (args.command == "sign") != (args.key is not None):
        parser.error("Supply --key only when signing.")
    try:
        if args.command == "sign":
            fingerprint = sign(args.output, args.key, args.trusted_key)
        else:
            from publish_release import validate
            fingerprint = verify(args.output, args.trusted_key)
            validate(args.output)
        print("Verified release publisher: " + fingerprint)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
