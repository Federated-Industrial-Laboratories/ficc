# SPDX-License-Identifier: Apache-2.0
"""Read bounded administrator configuration and private client credentials."""

import json
import math
import os
import re
import ssl
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


def text(value: object, maximum: int = 1024, minimum: int = 1) -> str:
    if (not isinstance(value, str) or not minimum <= len(value) <= maximum
            or any(ord(char) < 33 or ord(char) == 127 for char in value)):
        raise ValueError("The identity value is invalid.")
    return value


def timestamp(value: object) -> float:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0):
        raise ValueError("The identity time is invalid.")
    return float(value)


def pairs(values: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for name, value in values:
        if name in result:
            raise ValueError("The identity response has duplicate fields.")
        result[name] = value
    return result


class Decoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, object_pairs_hook=pairs, parse_constant=self.constant, **kwargs)

    @staticmethod
    def constant(_value: str):
        raise ValueError("The identity response has an invalid number.")


def document(raw: bytes) -> dict:
    try:
        result = json.loads(raw, cls=Decoder)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("The identity response is invalid.") from exc
    if not isinstance(result, dict):
        raise ValueError("The identity response must be an object.")
    return result


def https_url(value: object, *, origin_only: bool = False) -> tuple[str, str]:
    url = text(value, 2048)
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or parsed.query
            or "\\" in url or "%" in parsed.netloc or not url.isascii()
            or parsed.netloc != parsed.netloc.lower() or parsed.port == 0):
        raise ValueError("The identity endpoint must be an explicit HTTPS URL.")
    origin = "https://" + parsed.netloc
    if origin_only and url != origin:
        raise ValueError("An allowed origin must not contain a path.")
    if parsed.path and (not parsed.path.startswith("/") or "//" in parsed.path
                        or any(part in (".", "..") for part in parsed.path.split("/"))):
        raise ValueError("The identity endpoint path is invalid.")
    return url, origin


def private_file(value: object, *, secret: bool) -> bytes:
    path = Path(text(value, 4096))
    if not path.is_absolute():
        raise ValueError("The identity file must have an absolute path.")
    # Open each component without following links. A writable ancestor permits replacement.
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
                raise ValueError("The identity file directory is unsafe.")
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                        | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(child, "rb") as source:
            info = os.fstat(source.fileno())
            limit = 4096 if secret else 1024 * 1024
            forbidden = 0o077 if secret else 0o022
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or info.st_mode & (forbidden | 0o6000) or info.st_size > limit
                    or info.st_nlink != 1):
                raise ValueError("The identity file is unsafe.")
            raw = source.read(limit + 1)
            after = os.fstat(source.fileno())
            if (len(raw) > limit or len(raw) != info.st_size or
                    any(getattr(info, name) != getattr(after, name) for name in
                        ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
                raise ValueError("The identity file changed during the read.")
            return raw
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class Config:
    issuer: str
    callback: str
    client_id: str
    secret: str = field(repr=False)
    origins: frozenset[str]
    algorithms: tuple[str, ...]
    acr: tuple[str, ...]
    max_age: int
    session_seconds: int
    tls: ssl.SSLContext = field(repr=False)

    def endpoint(self, value: object) -> str:
        url, origin = https_url(value)
        if origin not in self.origins:
            raise ValueError("The identity endpoint origin is not allowed.")
        return url


def configuration(value: object, callback: str) -> Config:
    required = {"issuer", "client_id", "client_secret_file", "allowed_origins", "algorithms",
                "required_acr", "max_auth_age", "session_seconds"}
    if (not isinstance(value, dict) or not required <= value.keys()
            or value.keys() - required - {"ca_file"}):
        raise ValueError("The identity configuration is invalid.")
    issuer, _ = https_url(value["issuer"])
    callback, _ = https_url(callback)
    origins, algorithms, acr = (value[name] for name in
                                ("allowed_origins", "algorithms", "required_acr"))
    for values in (origins, algorithms, acr):
        if (not isinstance(values, list) or not 1 <= len(values) <= 16
                or any(not isinstance(item, str) for item in values)
                or len(set(values)) != len(values)):
            raise ValueError("The identity configuration list is invalid.")
    origins = frozenset(https_url(item, origin_only=True)[0] for item in origins)
    if not set(algorithms) <= {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                              "ES256", "ES384", "ES512"}:
        raise ValueError("The identity signing algorithm is unsupported.")
    for item in acr:
        text(item, 128)
    for name in ("max_auth_age", "session_seconds"):
        if type(value[name]) is not int or not 1 <= value[name] <= 86400:
            raise ValueError("The identity session limit must be from 1 to 86400 seconds.")
    secret = private_file(value["client_secret_file"], secret=True).decode("utf-8").rstrip("\r\n")
    if not secret or len(secret) > 4096 or any(ord(char) < 32 for char in secret):
        raise ValueError("The identity client secret is invalid.")
    tls = ssl.create_default_context()
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    if "ca_file" in value:
        tls.load_verify_locations(cadata=private_file(value["ca_file"], secret=False).decode("ascii"))
    result = Config(issuer, callback, text(value["client_id"], 256), secret, origins,
                    tuple(algorithms), tuple(acr), value["max_auth_age"],
                    value["session_seconds"], tls)
    result.endpoint(issuer)
    return result


def binding(value: object, *, challenge: bool = False) -> str:
    value = text(value, 128, 43 if challenge else 32)
    if not re.fullmatch(r"[A-Za-z0-9_~-]+", value) or (challenge and len(value) != 43):
        raise ValueError("The authentication binding is invalid.")
    return value
