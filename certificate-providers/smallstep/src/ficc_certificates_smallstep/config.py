# SPDX-License-Identifier: Apache-2.0
"""Read explicit authority settings and private signing material."""

import json
import os
import re
import ssl
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from joserfc.jwk import ECKey

IDENTIFIER = re.compile(r"[0-9a-f]{32}")


def identifier(value: object) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("The certificate identifier is invalid.")
    return value


def text(value: object, maximum: int = 256) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or not value.isascii() or any(ord(c) < 33 or ord(c) == 127 for c in value)):
        raise ValueError("The certificate setting is invalid.")
    return value


def document(raw: bytes) -> dict:
    def pairs(values):
        result = {}
        for name, value in values:
            if name in result:
                raise ValueError("Duplicate authority response field.")
            result[name] = value
        return result

    def constant(_value):
        raise ValueError("Invalid authority response number.")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(value, dict):
        raise ValueError("The authority response must be an object.")
    return value


def private_file(value: object, *, secret: bool) -> bytes:
    path = Path(text(value, 4096))
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise ValueError("The authority file path is invalid.")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022
                    and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
                raise ValueError("The authority file directory is unsafe.")
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                        | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(child, "rb") as source:
            info = os.fstat(source.fileno())
            limit = 4096 if secret else 16384
            forbidden = 0o077 if secret else 0o022
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or info.st_mode & (forbidden | 0o6000) or info.st_size > limit
                    or info.st_nlink != 1):
                raise ValueError("The authority file is unsafe.")
            raw = source.read(limit + 1)
            after = os.fstat(source.fileno())
            if (len(raw) > limit or len(raw) != info.st_size or
                    any(getattr(info, name) != getattr(after, name) for name in
                        ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
                raise ValueError("The authority file changed during the read.")
            return raw
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class Config:
    url: str
    installation: str
    provisioner: str
    kid: str
    roots: tuple[x509.Certificate, ...] = field(repr=False)
    tls: ssl.SSLContext = field(repr=False)
    seconds: int


def configuration(value: object) -> tuple[Config, ECKey]:
    try:
        required = {"ca_url", "installation_id", "provisioner", "signing_key_file", "root_file"}
        if (not isinstance(value, dict) or not required <= value.keys()
                or value.keys() - required - {"request_seconds"}):
            raise ValueError
        url = text(value["ca_url"], 1024)
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment or parsed.path
                or parsed.netloc != parsed.netloc.lower() or "%" in url or "\\" in url
                or parsed.port == 0):
            raise ValueError
        seconds = value.get("request_seconds", 15)
        if type(seconds) is not int or not 1 <= seconds <= 15:
            raise ValueError
        raw = document(private_file(value["signing_key_file"], secret=True))
        if (set(raw) - {"kty", "crv", "x", "y", "d", "alg", "use", "kid", "key_ops"}
                or raw.get("kty") != "EC" or raw.get("crv") != "P-256"
                or raw.get("alg", "ES256") != "ES256" or raw.get("use", "sig") != "sig"
                or raw.get("key_ops", ["sign"]) != ["sign"] or not raw.get("d")):
            raise ValueError
        key = ECKey.import_key(raw)
        kid = text(raw.get("kid"))
        pem = private_file(value["root_file"], secret=False)
        roots = x509.load_pem_x509_certificates(pem)
        if not 1 <= len(roots) <= 4:
            raise ValueError
        for root in roots:
            if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_verify_locations(cadata=pem.decode("ascii"))
        return (Config(url, identifier(value["installation_id"]), text(value["provisioner"]),
                       kid, tuple(roots), tls, seconds), key)
    except Exception:
        raise ValueError("The certificate provider configuration is invalid.") from None
