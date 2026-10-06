# SPDX-License-Identifier: Apache-2.0
"""Read agent observations through an explicit private controller connection."""

import ipaddress
import json
import os
import re
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .observation_schema import NODE_ID, Inventory, Reading

MAX_RESPONSE = 1024 * 1024
ERROR = "The observation failed. Check the private connection and current observation permissions."


def add_commands(commands):
    command = commands.add_parser("observe", help="Read approved inventory or resource observations as JSON.")
    command.add_argument("--connection", type=Path, required=True,
                         help="Private JSON file containing controller and token_file.")
    operations = command.add_subparsers(dest="observation", required=True)
    operations.add_parser("nodes", help="List machines permitted for disclosure.")
    resources = operations.add_parser("resources", help="Read a machine's cached resource sample.")
    resources.add_argument("--node", required=True)


def private_read(path: Path, maximum: int) -> bytes:
    """Open every path component without following symbolic links."""
    path = Path(os.path.abspath(path))
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=directory)
            os.close(directory)
            directory = next_directory
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_size > maximum):
                raise ValueError(ERROR)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                value = stream.read(maximum + 1)
            if len(value) > maximum:
                raise ValueError(ERROR)
            return value
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(ERROR)
        result[key] = value
    return result


def read_json(raw: bytes):
    def invalid(value):
        raise ValueError(ERROR)
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid)


def controller_origin(value: str) -> str:
    if not isinstance(value, str) or not value.isascii() or any(c.isspace() for c in value) or "\\" in value:
        raise ValueError(ERROR)
    parsed = urlsplit(value)
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or value.rstrip("/") != f"{parsed.scheme}://{parsed.netloc}"
            or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
        raise ValueError(ERROR)
    host = parsed.hostname
    if ":" in host:
        ipaddress.IPv6Address(host)
    elif not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
        raise ValueError(ERROR)
    if parsed.scheme == "http" and host not in {"127.0.0.1", "::1"}:
        raise ValueError(ERROR)
    return value.rstrip("/")


def execute(args) -> None:
    try:
        configuration = read_json(private_read(args.connection, 4096))
        if (not isinstance(configuration, dict) or set(configuration) != {"controller", "token_file"}
                or not isinstance(configuration["token_file"], str)):
            raise ValueError(ERROR)
        origin = controller_origin(configuration["controller"])
        token_path = Path(configuration["token_file"])
        if not token_path.is_absolute():
            raise ValueError(ERROR)
        token = private_read(token_path, 130).decode("ascii").removesuffix("\n")
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", token):
            raise ValueError(ERROR)
        path = "/api/v1/observations/nodes"
        if args.observation == "resources":
            if not NODE_ID.fullmatch(args.node):
                raise ValueError(ERROR)
            path += f"/{args.node}/resources"
        deadline = time.monotonic() + 15
        with httpx.Client(verify=True, trust_env=False, follow_redirects=False,
                          timeout=httpx.Timeout(10, connect=5),
                          headers={"Authorization": f"Bearer {token}",
                                   "Accept": "application/json", "Accept-Encoding": "identity"}) as client:
            with client.stream("GET", origin + path) as response:
                if (response.status_code != 200
                        or response.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                        or response.headers.get("content-encoding", "identity") != "identity"):
                    raise ValueError(ERROR)
                length = response.headers.get("content-length")
                if length is not None and (not length.isdigit() or int(length) > MAX_RESPONSE):
                    raise ValueError(ERROR)
                raw = bytearray()
                for chunk in response.iter_raw():
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE or time.monotonic() > deadline:
                        raise ValueError(ERROR)
        model = Inventory if args.observation == "nodes" else Reading
        value = model.model_validate(read_json(bytes(raw))).model_dump()
        if args.observation == "resources" and value["node_id"] != args.node:
            raise ValueError(ERROR)
        output = json.dumps(value, separators=(",", ":"), allow_nan=False)
        if len(output) + 1 > MAX_RESPONSE:
            raise ValueError(ERROR)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, httpx.HTTPError):
        raise ValueError(ERROR) from None
    print(output)
