# SPDX-License-Identifier: Apache-2.0
"""Manage module packages through temporary local owner credentials."""

import argparse
import json
import os
import re
import stat
from contextlib import suppress
from pathlib import Path

import httpx

from .settings import default_state_dir


def digest(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError("Use a lowercase SHA-256 digest.")
    return value


def identity(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise argparse.ArgumentTypeError("Use a 32-character lowercase hexadecimal identity.")
    return value


def add_commands(commands):
    for name in ("inspect", "install", "list", "supplied", "sandbox", "enable", "disable", "remove", "run"):
        item = commands.add_parser("module-" + name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name in {"inspect", "install"}:
            source = item.add_mutually_exclusive_group(required=True)
            source.add_argument("--file", type=Path)
            source.add_argument("--url")
            source.add_argument("--supplied", help="Package ID from the supplied module list.")
            item.add_argument("--expected-digest", type=digest, required=name == "install")
            item.add_argument("--allow-private-network", action="store_true")
            item.add_argument("--allow-http", action="store_true")
            if name == "install":
                item.add_argument("--accept-unverified", action="store_true", required=True,
                                  help="Accept a package without verified publisher identity.")
        elif name in {"enable", "disable", "remove"}:
            item.add_argument("digest", type=digest)
            if name == "enable":
                item.add_argument("--grants", type=Path, required=True,
                                  help="JSON grant list. Use [] for a package without capabilities.")
            elif name == "remove":
                item.add_argument("--confirm", action="store_true", required=True)
        elif name == "run":
            item.add_argument("--workspace", type=identity, required=True)
            item.add_argument("--instance", type=identity, required=True)
            item.add_argument("--action", required=True)
            item.add_argument("--target", type=identity, action="append", required=True)
            item.add_argument("--parameters", type=Path)


def read_file(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("The input must be a regular file within the size limit.")
        value = stream.read(limit + 1)
        if len(value) > limit:
            raise ValueError("The input exceeds the size limit.")
        return value


def json_file(path: Path, kind):
    try:
        value = json.loads(read_file(path, 65536))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("The input must contain bounded JSON.") from exc
    if not isinstance(value, kind):
        raise ValueError("The JSON input has the wrong type.")
    return value


def result(response: httpx.Response):
    if response.is_error:
        try:
            message = response.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            response.raise_for_status()
        else:
            if isinstance(message, str):
                raise ValueError(message)
            response.raise_for_status()
    return response.json()


def execute(args):
    from .cli import local_request
    source = read_file(args.file, 16 * 1024 * 1024) if getattr(args, "file", None) else None
    grants = json_file(args.grants, list) if args.command == "module-enable" else []
    parameters = json_file(args.parameters, dict) if getattr(args, "parameters", None) else {}
    grant = local_request(args.state_dir, {"action": "ephemeral"})
    preview = None
    try:
        with httpx.Client(base_url=grant["origin"], headers={"Authorization": "Bearer " + grant["credential"]},
                          timeout=45, trust_env=False, follow_redirects=False) as client:
            try:
                if args.command in {"module-inspect", "module-install"}:
                    if source is not None:
                        response = client.post("/api/v1/module-install-previews", content=source,
                                               headers={"Content-Type": "application/octet-stream"})
                    elif args.supplied:
                        response = client.post("/api/v1/supplied-module-previews", json={"package_id": args.supplied})
                    else:
                        response = client.post("/api/v1/module-fetch-previews", json={"url": args.url,
                            "expected_digest": args.expected_digest, "allow_http": args.allow_http,
                            "allow_private_network": args.allow_private_network})
                    value = result(response)
                    preview = value["preview_id"]
                    if args.expected_digest and value["digest"] != args.expected_digest:
                        raise ValueError("The package does not match the expected digest.")
                    if args.command == "module-install":
                        value = result(client.post("/api/v1/modules", json={"preview_id": preview,
                            "digest": args.expected_digest, "accept_unverified": args.accept_unverified}))
                    else:
                        value.pop("preview_id")
                        value.pop("expires_at", None)
                elif args.command == "module-supplied":
                    value = result(client.get("/api/v1/supplied-modules"))
                elif args.command in {"module-list", "module-sandbox"}:
                    suffix = "/sandbox" if args.command == "module-sandbox" else ""
                    value = result(client.get("/api/v1/modules" + suffix))
                elif args.command in {"module-enable", "module-disable"}:
                    value = result(client.post(f"/api/v1/modules/{args.digest}/activation", json={
                        "enabled": args.command == "module-enable", "grants": grants}))
                elif args.command == "module-remove":
                    value = result(client.delete(f"/api/v1/modules/{args.digest}"))
                else:
                    value = result(client.post("/api/v1/module-invocations", json={
                        "workspace_id": args.workspace, "instance_id": args.instance,
                        "action": args.action, "targets": args.target, "parameters": parameters}))
                print(json.dumps(value, indent=2))
            finally:
                if preview:
                    with suppress(httpx.HTTPError):
                        client.delete("/api/v1/module-install-previews/" + preview)
    finally:
        with suppress(OSError, ValueError):
            local_request(args.state_dir, {"action": "revoke", "id": grant["id"]})
