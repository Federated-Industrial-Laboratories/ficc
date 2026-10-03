# SPDX-License-Identifier: Apache-2.0
"""Validate explicit remote origin and private gateway configuration."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .state_provider import read_private

CONFIG = "remote.json"


def https_url(value: str, *, origin: bool = False) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or not value.isascii():
        raise ValueError("Select a complete HTTPS address.")
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError:
        raise ValueError("The HTTPS address is invalid.") from None
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.password is not None or url.query or url.fragment or "?" in value or "#" in value
            or any(ord(char) <= 32 or ord(char) == 127 for char in value) or "\\" in value
            or port is not None and not 1 <= port <= 65535
            or origin and url.path or url.netloc.lower() != url.netloc):
        raise ValueError("Use an exact HTTPS address without credentials, query or fragment.")
    return value


@dataclass(frozen=True)
class RemoteSettings:
    origin: str
    socket: Path
    secret: str = field(repr=False)


def configuration(state: Path) -> RemoteSettings | None:
    path = state / CONFIG
    if not path.exists() and not path.is_symlink():
        return None
    value = json.loads(read_private(path))
    if not isinstance(value, dict) or set(value) != {"origin", "socket", "gateway_secret_file"}:
        raise ValueError("The remote gateway configuration is invalid.")
    origin = https_url(value["origin"], origin=True)
    socket = Path(value["socket"])
    secret_file = Path(value["gateway_secret_file"])
    if not socket.is_absolute() or len(str(socket).encode()) > 100 or not secret_file.is_absolute():
        raise ValueError("Use absolute private gateway paths and a socket path of at most 100 bytes.")
    secret = read_private(secret_file, 256).decode("ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", secret):
        raise ValueError("Use a random gateway credential with at least 256 bits of entropy.")
    return RemoteSettings(origin, socket, secret)
