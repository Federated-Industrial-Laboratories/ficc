# SPDX-License-Identifier: Apache-2.0
"""Purpose-separated FICC signatures bind pairing and requests to verified streams."""
import hashlib
import json
import os
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..errors import Failure
from ..settings import private_directory


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def sign(key, value):
    return {"payload": value, "signature": key.sign(b"FICC-Federation-1\0" + encode(value)).hex()}


def verify(envelope, public):
    try:
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError("Envelope fields differ.")
        raw = encode(envelope["payload"])
        if len(raw) > 512*1024 or len(public) != 64 or len(envelope["signature"]) != 128:
            raise ValueError("Envelope exceeds its bounds.")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
            bytes.fromhex(envelope["signature"]), b"FICC-Federation-1\0" + raw)
        return envelope["payload"]
    except (ValueError, TypeError, KeyError, InvalidSignature):
        raise Failure("federation_signature", "The FICC identity signature is invalid.", 403) from None


def key(directory):
    private_directory(directory)
    path = directory / "Identity.key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        try:
            value = Ed25519PrivateKey.generate().private_bytes_raw()
            if os.write(fd, value) != len(value):
                raise OSError("FICC identity write was incomplete.")
            os.fsync(fd)
        finally:
            os.close(fd)
        folder = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != 32):
            raise ValueError("The FICC federation identity requires one private owned 32-byte file.")
        return Ed25519PrivateKey.from_private_bytes(os.read(fd, 33))
    finally:
        os.close(fd)
