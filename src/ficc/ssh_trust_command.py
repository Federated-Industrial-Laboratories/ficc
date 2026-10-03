# SPDX-License-Identifier: Apache-2.0
"""Validate the host certificate supplied by OpenSSH and record its exact bytes."""

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import SSHCertificateType

from .ssh_trust import (
    MAX_CERTIFICATE,
    MAX_KRL,
    TRUST_ERRORS,
    certificate,
    read_private,
    revocation,
    snapshot,
    write_private,
)


def verify(directory: Path, reason: str, kind: str, key: str) -> str:
    if reason == "ORDER":
        return ""
    if reason != "HOSTNAME" or "-cert-v01@openssh.com" not in kind or len(key) > MAX_CERTIFICATE:
        raise ValueError("The SSH host certificate is unavailable.")
    binding = json.loads(read_private(directory / "binding.json"))
    selected = snapshot(Path(binding["state"]), binding["profile"])
    if selected is None or selected["digest"] != binding["digest"]:
        raise ValueError("The SSH trust configuration changed.")
    raw = f"{kind} {key}".encode("ascii")
    principal = selected["profile"]["host_principal"]
    certificate(raw, SSHCertificateType.HOST, principal, selected["ca"].encode())
    proof = directory / "candidate.pub"
    try:
        write_private(proof, raw)
        revocation(read_private(Path(selected["profile"]["revoked_keys"]), MAX_KRL), [proof], directory)
        proof.rename(directory / "host.pub")
    finally:
        proof.unlink(missing_ok=True)
    return f"@cert-authority {principal} {selected['ca']}\n"


def main() -> int:
    try:
        if len(sys.argv) != 5:
            raise ValueError("The SSH trust command arguments are invalid.")
        print(verify(Path(sys.argv[1]), *sys.argv[2:]), end="")
        return 0
    except TRUST_ERRORS:
        print("The SSH certificate was refused by the current trust policy.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
