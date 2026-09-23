# SPDX-License-Identifier: Apache-2.0
"""Run the local service and access its authenticated API."""

import argparse
import json
import os
import socket
import stat
import sys
from contextlib import suppress
from pathlib import Path

import httpx
import uvicorn

from . import launcher
from .api import create_app
from .launcher_config import config_path
from .settings import Settings, default_state_dir, private_directory


def local_request(state_dir: Path, request: dict) -> dict:
    private_directory(state_dir)
    path = state_dir / "control.sock"
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("The local service socket is not private.")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(str(path))
        stream.sendall(json.dumps(request).encode() + b"\n")
        response = bytearray()
        while b"\n" not in response:
            block = stream.recv(4096)
            if not block:
                raise ValueError("The local service closed the connection.")
            response.extend(block)
            if len(response) > 8192:
                raise ValueError("The local response exceeds the limit.")
    value = json.loads(response)
    if "error" in value:
        raise ValueError("The local service refused the request.")
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="ficc", description="Local cluster management console.")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("serve", "open", "nodes", "token-create", "token-revoke", "enroll", "refresh"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name == "serve":
            item.add_argument("--port", type=int, default=8170)
            item.add_argument("--profile", action="append", default=[])
            item.add_argument("--ssh-config", type=Path)
            item.add_argument("--demo", action="store_true")
        elif name == "open":
            item.add_argument("--print-url", action="store_true")
        elif name == "token-create":
            item.add_argument("--label", required=True)
            item.add_argument("--scope", action="append", required=True)
            item.add_argument("--node", action="append")
            item.add_argument("--lifetime", type=int, default=3600)
            item.add_argument("--output", type=Path, required=True)
        elif name == "token-revoke":
            item.add_argument("id")
        elif name == "enroll":
            item.add_argument("--profile", required=True)
            item.add_argument("--name", required=True)
            item.add_argument("--fingerprint")
            item.add_argument("--install-helper", action="store_true")
        elif name == "refresh":
            item.add_argument("node_ids", nargs="+")
    for name in ("install-launcher", "start", "status", "stop", "launch"):
        item = commands.add_parser(name)
        item.add_argument("--launcher-config", type=Path, default=config_path())
        if name == "install-launcher":
            item.add_argument("--state-dir", type=Path, default=default_state_dir())
            item.add_argument("--port", type=int, default=8170)
            item.add_argument("--profile", action="append", default=[])
            item.add_argument("--ssh-config", type=Path)
            item.add_argument("--demo", action="store_true")
            item.add_argument("--name", default="ficc")
            item.add_argument("--autostart", action="store_true")
    from .job_cli import add_commands
    add_commands(commands)
    return result


def api_command(args) -> None:
    grant = local_request(args.state_dir, {"action": "ephemeral"})
    try:
        with httpx.Client(base_url=grant["origin"], headers={"Authorization": "Bearer " + grant["credential"]},
                          timeout=90, trust_env=False) as client:
            if args.command == "nodes":
                response = client.get("/api/v1/nodes")
            elif args.command == "refresh":
                response = client.post("/api/v1/nodes/refresh", json={"node_ids": args.node_ids})
            else:
                response = client.post("/api/v1/node-previews", json={"profile": args.profile, "name": args.name})
                response.raise_for_status()
                preview = response.json()
                if args.fingerprint:
                    response = client.post("/api/v1/nodes", json={"preview_id": preview["preview_id"],
                                           "expected_fingerprint": args.fingerprint,
                                           "install_helper": args.install_helper})
            response.raise_for_status()
            print(json.dumps(response.json(), indent=2))
    finally:
        with suppress(OSError, ValueError):
            local_request(args.state_dir, {"action": "revoke", "id": grant["id"]})


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "serve":
            os.umask(0o077)
            settings = Settings(state_dir=args.state_dir, port=args.port, profiles=tuple(args.profile),
                                ssh_config=args.ssh_config, demo=args.demo)
            uvicorn.run(create_app(settings), host="127.0.0.1", port=settings.port,
                        access_log=False, proxy_headers=False, server_header=False,
                        limit_concurrency=64, timeout_keep_alive=5)
        elif args.command == "open":
            launcher.open_console(args.state_dir, args.print_url)
        elif args.command == "install-launcher":
            print(json.dumps(launcher.install(args), indent=2))
        elif args.command == "start":
            config = launcher.start(args.launcher_config)
            print(json.dumps({"ready": True, "origin": f"http://127.0.0.1:{config.port}"}))
        elif args.command in {"status", "stop"}:
            print(json.dumps(getattr(launcher, args.command)(args.launcher_config), indent=2))
        elif args.command == "launch":
            launcher.launch(args.launcher_config)
        elif args.command.startswith("job-") or args.command == "helper-upgrade":
            from .job_cli import execute
            execute(args)
        elif args.command == "token-create":
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                grant = local_request(args.state_dir, {"action": "token", "label": args.label,
                                      "scopes": args.scope, "node_ids": args.node,
                                      "lifetime": args.lifetime})
                with os.fdopen(fd, "w") as stream:
                    fd = -1
                    stream.write(grant["credential"] + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                if fd >= 0:
                    os.close(fd)
                args.output.unlink()
                raise
            print(json.dumps({"id": grant["id"], "expires_at": grant["expires_at"]}))
        elif args.command == "token-revoke":
            local_request(args.state_dir, {"action": "revoke", "id": args.id})
            print('{"ok":true}')
        else:
            api_command(args)
        return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        if args.command == "launch":
            launcher.notify_failure(str(exc))
        return 1
    except (OSError, httpx.HTTPError):
        print("The request failed. Check service access, permissions, and connection settings.", file=sys.stderr)
        if args.command == "launch":
            launcher.notify_failure("FICC could not start. Run ficc status in a terminal for details.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
