# SPDX-License-Identifier: Apache-2.0
"""Run the local service and access its authenticated API."""

import argparse
import json
import os
import socket
import sqlite3
import stat
import sys
from contextlib import suppress
from pathlib import Path

import httpx

from . import __version__, launcher
from .launcher_config import config_path
from .local_client import client as local_client
from .settings import Settings, default_state_dir, private_directory


def local_request(state_dir: Path, request: dict) -> dict:
    private_directory(state_dir)
    path = state_dir / "control.sock"
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("The local service socket is not private.")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(60)
        stream.connect(str(path))
        stream.sendall(json.dumps(request).encode() + b"\n")
        response = bytearray()
        while b"\n" not in response:
            block = stream.recv(4096)
            if not block:
                raise ValueError("The local service closed the connection.")
            response.extend(block)
            if len(response) > 524288:
                raise ValueError("The local response exceeds the limit.")
    value = json.loads(response)
    if "error" in value:
        raise ValueError(value.get("message", "The local service refused the request."))
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="ficc", description="Local cluster management console.")
    result.add_argument("--version", action="version", version="FICC " + __version__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("serve", "open", "nodes", "token-create", "token-revoke", "enroll", "refresh"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name == "serve":
            item.add_argument("--port", type=int, default=8170)
            item.add_argument("--profile", action="append", default=[])
            item.add_argument("--ssh-config", type=Path)
            item.add_argument("--viewer-runtime", type=Path, help="Path to the isolated native display runtime.")
            item.add_argument("--windows-runtime", type=Path, help="Path to the isolated Windows transport runtime.")
            item.add_argument("--demo", action="store_true")
        elif name == "open":
            item.add_argument("--print-url", action="store_true")
            item.add_argument("--subject")
            item.add_argument("--project")
        elif name == "token-create":
            item.add_argument("--subject")
            item.add_argument("--project")
            item.add_argument("--label", required=True)
            item.add_argument("--scope", action="append", required=True)
            item.add_argument("--node", action="append")
            item.add_argument("--root", action="append")
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
    for name in ("install-launcher", "start", "status", "stop", "launch", "desktop"):
        item = commands.add_parser(name)
        item.add_argument("--launcher-config", type=Path, default=config_path())
        if name in {"install-launcher", "desktop"}:
            def initial(value):
                return argparse.SUPPRESS if name == "desktop" else value

            item.add_argument("--state-dir", type=Path, default=initial(default_state_dir()))
            item.add_argument("--port", type=int, default=initial(8170))
            item.add_argument("--profile", action="append", default=initial([]))
            item.add_argument("--ssh-config", type=Path, default=initial(None))
            item.add_argument("--demo", action="store_true", default=initial(False))
            item.add_argument("--name", default=initial("ficc"))
            if name == "install-launcher":
                item.add_argument("--autostart", action="store_true")
    from .job_cli import add_commands
    add_commands(commands)
    from .file_cli import add_commands as add_file_commands
    add_file_commands(commands)
    from .workloads.cli import add_commands as add_workload_commands
    add_workload_commands(commands)
    from .backup import add_commands as add_backup_commands
    add_backup_commands(commands)
    from .history import add_commands as add_history_commands
    add_history_commands(commands)
    from .agent_cli import add_commands as add_agent_commands
    add_agent_commands(commands)
    from .module_cli import add_commands as add_module_commands
    add_module_commands(commands)
    from .identity_cli import add_commands as add_identity_commands
    add_identity_commands(commands)
    from .state_cli import add_commands as add_state_commands
    add_state_commands(commands)
    from .policy_cli import add_commands as add_policy_commands
    add_policy_commands(commands)
    from .remote_cli import add_commands as add_remote_commands
    add_remote_commands(commands)
    from .contributor_cli import add_commands as add_contributor_commands
    add_contributor_commands(commands)
    from .secret_cli import add_commands as add_secret_commands
    add_secret_commands(commands)
    from .audit_cli import add_commands as add_audit_commands
    add_audit_commands(commands)
    return result


def api_command(args) -> None:
    grant = local_request(args.state_dir, {"action": "ephemeral"})
    try:
        with local_client(grant, args.state_dir) as client:
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
    args = parser().parse_args((sys.argv[1:] if argv is None else argv) or ["desktop"])
    try:
        if args.command == "serve":
            os.umask(0o077)
            settings = Settings(state_dir=args.state_dir, port=args.port, profiles=tuple(args.profile),
                                ssh_config=args.ssh_config, demo=args.demo, viewer_runtime=args.viewer_runtime,
                                windows_runtime=args.windows_runtime)
            from .remote_server import serve
            serve(settings)
        elif args.command in {"remote-configure", "identity-provider-configure"}:
            from .remote_cli import execute as execute_remote
            execute_remote(args)
        elif args.command.startswith(("contributor-", "node-")) or args.command == "contributors-configure":
            from .contributor_cli import execute as execute_contributors
            execute_contributors(args)
        elif args.command.startswith("workload-") or args.command == "workloads-configure":
            from .workloads.cli import execute as execute_workloads
            execute_workloads(args)
        elif args.command in {"state-configure", "state-migrate"}:
            from .state_cli import execute as execute_state
            execute_state(args)
        elif args.command.startswith("secret-"):
            from .secret_cli import execute as execute_secrets
            execute_secrets(args)
        elif args.command.startswith("audit-"):
            from .audit_cli import execute as execute_audit
            execute_audit(args)
        elif args.command == "archive-history":
            from .history import execute as execute_history
            execute_history(args)
        elif args.command in {"backup", "restore"}:
            from .backup import execute as execute_backup
            execute_backup(args)
        elif args.command == "open":
            launcher.open_console(args.state_dir, args.print_url, subject=args.subject, project=args.project)
        elif args.command == "install-launcher":
            print(json.dumps(launcher.install(args), indent=2))
        elif args.command == "start":
            config = launcher.start(args.launcher_config)
            print(json.dumps({"ready": True, "origin": f"http://127.0.0.1:{config.port}"}))
        elif args.command in {"status", "stop"}:
            print(json.dumps(getattr(launcher, args.command)(args.launcher_config), indent=2))
        elif args.command == "launch":
            launcher.launch(args.launcher_config)
        elif args.command == "desktop":
            options = {key: value for key, value in vars(args).items()
                       if key not in {"command", "launcher_config"}}
            launcher.desktop(args.launcher_config, options)
        elif args.command.startswith("job-") or args.command == "helper-upgrade":
            from .job_cli import execute
            execute(args)
        elif args.command.startswith(("agent-profile-", "bus-")):
            from .agent_cli import execute as execute_agents
            execute_agents(args)
        elif args.command.startswith("root-"):
            from .file_cli import execute as execute_files
            execute_files(args)
        elif args.command.startswith(("identity-", "project-")):
            from .identity_cli import execute as execute_identities
            execute_identities(args)
        elif args.command.startswith("policy-"):
            from .policy_cli import execute as execute_policy
            execute_policy(args)
        elif args.command.startswith("module-"):
            from .module_cli import execute as execute_modules
            execute_modules(args)
        elif args.command == "token-create":
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                grant = local_request(args.state_dir, {"action": "token", "label": args.label,
                                      "scopes": args.scope, "node_ids": args.node, "root_ids": args.root,
                                      "lifetime": args.lifetime,
                                      **({"subject_id": args.subject} if args.subject else {}),
                                      **({"project_id": args.project} if args.project else {})})
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
        if args.command in {"launch", "desktop"}:
            launcher.notify_failure(str(exc))
        return 1
    except sqlite3.Error:
        message = "The state database is unavailable. Check connection settings, ownership, and pending writes."
        print(message, file=sys.stderr)
        if args.command in {"launch", "desktop"}:
            launcher.notify_failure(message)
        return 1
    except (OSError, httpx.HTTPError):
        print("The request failed. Check service access, permissions, and connection settings.", file=sys.stderr)
        if args.command in {"launch", "desktop"}:
            launcher.notify_failure("FICC could not start. Run ficc status in a terminal for details.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
