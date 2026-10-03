#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Generate a private Smallstep profile from existing public configuration.
# Inputs: CA directory, public JWK, installation ID. Output: JSON. Exit: 0 or 1.
"""Write a node-only authority profile without copying private keys."""

import argparse
import json
import os
import re
from pathlib import Path


def profile(directory: Path, public_key: dict, installation: str, port: int) -> dict:
    if not re.fullmatch(r"[0-9a-f]{32}", installation) or not 1024 <= port <= 65535:
        raise ValueError("Invalid installation or port.")
    if (set(public_key) - {"kty", "crv", "x", "y", "alg", "kid", "use", "key_ops"}
            or public_key.get("kty") != "EC" or public_key.get("crv") != "P-256"
            or not {"x", "y", "kid"} <= public_key.keys()):
        raise ValueError("Use a public P-256 provisioner key.")
    template = (Path(__file__).parent / "node.tpl").read_text().replace("INSTALLATION_ID", installation)
    return {
        "root": str(directory / "certs/root_ca.crt"),
        "crt": str(directory / "certs/intermediate_ca.crt"),
        "key": str(directory / "secrets/intermediate_ca_key"),
        "address": f"127.0.0.1:{port}", "dnsNames": ["localhost", "127.0.0.1"],
        "db": {"type": "badgerv2", "dataSource": str(directory / "db")},
        "authority": {"backdate": "0s", "provisioners": [{
            "type": "JWK", "name": "ficc-nodes", "key": public_key,
            "claims": {"minTLSCertDuration": "1m", "maxTLSCertDuration": "24h",
                       "defaultTLSCertDuration": "1h", "disableRenewal": True,
                       "allowRenewalAfterExpiry": False, "enableSSHCA": False},
            "options": {"x509": {"template": template}},
        }]},
        "crl": {"enabled": True, "generateOnRevoke": True,
                "cacheDuration": "5m", "renewPeriod": "1m"},
        "tls": {"minVersion": 1.2, "maxVersion": 1.3},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--public-jwk", type=Path, required=True)
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = args.public_jwk.read_bytes()
        if len(raw) > 4096 or not args.directory.is_absolute():
            raise ValueError
        value = profile(args.directory, json.loads(raw), args.installation_id, args.port)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(json.dumps(value, indent=2) + "\n")
    except Exception:
        parser.exit(1, "The authority profile could not be written.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
