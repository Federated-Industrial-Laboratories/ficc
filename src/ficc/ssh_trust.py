# SPDX-License-Identifier: Apache-2.0
"""Load private SSH authority policy and validate current certificate trust."""

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    SSHCertificate,
    SSHCertificateType,
    load_ssh_public_identity,
    load_ssh_public_key,
)

from .errors import Failure
from .settings import MAX_NODES, PROFILE
from .state_provider import read_private

CONFIG = "ssh-trust.json"
CA_KEY_TYPE = "ficc-ssh-ca-v1"
PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,252}\Z")
MAX_CERTIFICATE = 65536
MAX_KRL = 4 * 1024 * 1024


def denied() -> Failure:
    return Failure("ssh_trust_revoked", "SSH certificate trust is invalid, changed, expired or revoked.", 409)


def public_bytes(key) -> bytes:
    return key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)


def private_path(value) -> Path:
    if (not isinstance(value, str) or not value.startswith("/") or len(value) > 4096
            or any(ord(char) < 33 or char in "%$\\\"'" for char in value)):
        raise ValueError("Use an absolute private SSH trust path without expansion characters.")
    return Path(value)


def configuration(state: Path, profile: str) -> dict | None:
    path = state / CONFIG
    if not path.exists() and not path.is_symlink():
        return None
    value = json.loads(read_private(path))
    if (not isinstance(value, dict) or set(value) != {"version", "profiles"}
            or type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["profiles"], dict) or len(value["profiles"]) > MAX_NODES):
        raise ValueError("The SSH trust configuration is invalid.")
    for name, item in value["profiles"].items():
        if (not isinstance(name, str) or not PROFILE.fullmatch(name) or not isinstance(item, dict)
                or set(item) not in ({"host_ca", "host_principal", "revoked_keys"},
                                    {"host_ca", "host_principal", "revoked_keys", "user"})):
            raise ValueError("The SSH certificate profile is invalid.")
        for field in ("host_ca", "revoked_keys"):
            private_path(item[field])
        if not isinstance(item["host_principal"], str) or not PRINCIPAL.fullmatch(item["host_principal"]):
            raise ValueError("The SSH host principal must be explicit.")
        if "user" in item:
            user = item["user"]
            if not isinstance(user, dict) or set(user) != {"certificate", "identity_file", "principal"}:
                raise ValueError("The SSH user certificate configuration is invalid.")
            private_path(user["certificate"])
            private_path(user["identity_file"])
            if not isinstance(user["principal"], str) or not PRINCIPAL.fullmatch(user["principal"]):
                raise ValueError("The SSH user principal must be explicit.")
    return value["profiles"].get(profile)


def snapshot(state: Path, profile: str) -> dict | None:
    item = configuration(state, profile)
    if item is None:
        return None
    ca = public_bytes(load_ssh_public_key(read_private(Path(item["host_ca"]), MAX_CERTIFICATE)))
    certificate = read_private(Path(item["user"]["certificate"]), MAX_CERTIFICATE) if "user" in item else b""
    payload = {"profile": item, "ca": ca.decode("ascii"), "user_certificate": certificate.decode("ascii")}
    payload["digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return payload


def certificate(raw: bytes, kind: SSHCertificateType, principal: str,
                ca: bytes | None = None) -> SSHCertificate:
    value = load_ssh_public_identity(raw)
    if not isinstance(value, SSHCertificate) or value.type != kind:
        raise ValueError("The SSH certificate type is invalid.")
    if (principal.encode("ascii") not in value.valid_principals
            or not value.valid_after <= time.time() < value.valid_before):
        raise ValueError("The SSH certificate principal or lifetime is invalid.")
    if ca is not None and public_bytes(value.signature_key()) != ca:
        raise ValueError("The SSH certificate authority is not approved.")
    if kind == SSHCertificateType.HOST and value.critical_options:
        raise ValueError("The SSH host certificate has unsupported critical options.")
    value.verify_cert_signature()
    return value


def write_private(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def revocation(krl: bytes, paths: list[Path], directory: Path) -> None:
    if not krl.startswith(b"SSHKRL\n\x00"):
        raise ValueError("Use a valid OpenSSH key revocation list.")
    path = directory / ("krl-" + hashlib.sha256(krl).hexdigest())
    if not path.exists():
        write_private(path, krl)
    result = subprocess.run(["ssh-keygen", "-Q", "-f", str(path), *map(str, paths)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=2, check=False)
    if result.returncode:
        raise ValueError("The SSH certificate or its key is revoked, or its revocation list is invalid.")
    for previous in directory.glob("krl-*"):
        if previous != path:
            previous.unlink(missing_ok=True)


TRUST_ERRORS = (OSError, ValueError, TypeError, KeyError, InvalidSignature,
                UnsupportedAlgorithm, subprocess.SubprocessError)
