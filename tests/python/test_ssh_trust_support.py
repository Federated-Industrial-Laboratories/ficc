# SPDX-License-Identifier: Apache-2.0
"""Create distinct SSH certificate identities and private revocation fixtures."""

import json
import os
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    SSHCertificateBuilder,
    SSHCertificateType,
)

from ficc.settings import private_directory
from ficc.ssh_trust import CA_KEY_TYPE, public_bytes


def save(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def key_files(path: Path):
    key = Ed25519PrivateKey.generate()
    save(path, key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    save(path.with_suffix(".pub"), public_bytes(key.public_key()))
    return key


def signed(key, ca, principal, serial, *, user=False, before=None, after=None):
    now = int(time.time())
    builder = (SSHCertificateBuilder().public_key(key.public_key()).serial(serial)
               .type(SSHCertificateType.USER if user else SSHCertificateType.HOST)
               .key_id(f"fixture-{serial}".encode()).valid_principals([principal.encode()])
               .valid_after(now - 60 if after is None else after)
               .valid_before(now + 3600 if before is None else before))
    if user:
        builder = builder.add_extension(b"permit-pty", b"")
    return builder.sign(ca).public_bytes()


def krl(path: Path, *revoked: Path):
    candidate = path.with_suffix(".next")
    candidate.unlink(missing_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-k", "-f", str(candidate),
                    *map(str, revoked or (Path("/dev/null"),))], check=True, capture_output=True)
    candidate.chmod(0o600)
    os.replace(candidate, path)


def fixture(root: Path, count: int, *, user=True):
    state = root / "state"
    private_directory(state)
    material = root / "certificates"
    material.mkdir(mode=0o700)
    ca = key_files(material / "ca")
    ca_line = public_bytes(ca.public_key()).decode()
    revoked = material / "revoked.krl"
    krl(revoked)
    records = []
    profiles = {}
    for index in range(count):
        name = f"fixture-{index}"
        principal = f"machine-{index}.example"
        host = key_files(material / f"host-{index}")
        host_certificate = save(material / f"host-{index}-cert.pub", signed(host, ca, principal, index + 1))
        client = key_files(material / f"client-{index}")
        user_principal = f"operator-{index}"
        user_certificate = save(material / f"client-{index}-cert.pub", signed(
            client, ca, user_principal, index + 1001, user=True))
        profiles[name] = {"host_ca": str(material / "ca.pub"), "host_principal": principal,
                          "revoked_keys": str(revoked)}
        if user:
            profiles[name]["user"] = {"certificate": str(user_certificate),
                                      "identity_file": str(material / f"client-{index}"),
                                      "principal": user_principal}
        node = {"id": f"node-{index}", "name": name, "profile": name, "host": "127.0.0.1",
                "account": user_principal, "port": 22, "host_principal": principal,
                "key_type": CA_KEY_TYPE, "key": ca_line.split()[1]}
        config = {"hostname": "127.0.0.1", "user": user_principal, "port": 22,
                  "identityfiles": [str(material / f"client-{index}")], "resolved_digest": name,
                  "hostkeyalgorithms": "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519",
                  "pubkeyacceptedalgorithms": "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519"}
        records.append({"node": node, "config": config, "host": host, "client": client,
                        "host_certificate": host_certificate, "user_certificate": user_certificate})
    save(state / "ssh-trust.json", json.dumps({"version": 1, "profiles": profiles}).encode())
    return state, ca, revoked, profiles, records
