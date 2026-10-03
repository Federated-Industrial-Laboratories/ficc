# SPDX-License-Identifier: Apache-2.0
"""Configure contributor ingress and operate private node enrollment files."""

import asyncio
import json
import os
from pathlib import Path

from .contributor_client_state import NodeState, default_state
from .launcher_config import write_file
from .settings import Settings, default_state_dir, private_directory
from .state_lock import StateLock
from .state_provider import read_private


def add_commands(commands):
    for name in ("contributors-configure", "contributor-list", "contributor-invite", "contributor-approve", "contributor-disable", "contributor-remove"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name == "contributors-configure":
            item.add_argument("--input", type=Path, required=True)
        else:
            item.add_argument("--project")
        if name == "contributor-invite":
            item.add_argument("--name", required=True)
            item.add_argument("--mode", choices=("managed", "voluntary"), required=True)
            item.add_argument("--output", type=Path, required=True)
        if name in {"contributor-approve", "contributor-disable", "contributor-remove"}:
            item.add_argument("id")
            item.add_argument("--revision", type=int, required=True)
        if name == "contributor-approve":
            item.add_argument("--public-key", required=True)
    for name in ("node-join", "node-connect", "node-status", "node-rotate"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state())
        if name == "node-join":
            item.add_argument("--invitation", type=Path, required=True)
            item.add_argument("--server-ca", type=Path)
        if name == "node-connect":
            item.add_argument("--transport", choices=("auto", "persistent", "polling"), default="auto")
            item.add_argument("--once", action="store_true")
            item.add_argument("--executor-socket", type=Path)


def execute(args):
    if args.command == "contributors-configure":
        private_directory(args.state_dir)
        value = json.loads(read_private(args.input))
        with StateLock(args.state_dir):
            path = args.state_dir / "contributors.json"
            previous = read_private(path) if path.exists() or path.is_symlink() else None
            try:
                write_file(path, json.dumps(value, indent=2) + "\n")
                Settings(state_dir=args.state_dir)
            except BaseException:
                if previous is None:
                    path.unlink(missing_ok=True)
                else:
                    write_file(path, previous.decode())
                raise
        print(json.dumps({"configured": True, "restart_required": True}))
        return
    if args.command.startswith("node-"):
        from . import contributor_client
        state = NodeState(args.state_dir)
        if args.command == "node-status":
            value = state.load()
            material = value.get("current", value.get("pending", {}))
            print(json.dumps({"node_id": value["node_id"], "stage": value["stage"],
                              "controller": value["controller"], "public_key": material.get("public_key"),
                              "certificate_expires_at": material.get("expires_at")}))
            return
        with StateLock(state.path):
            if args.command == "node-join":
                result = asyncio.run(contributor_client.join(state, args.invitation, args.server_ca))
            elif args.command == "node-connect":
                result = asyncio.run(contributor_client.run(state, args.transport, args.once, args.executor_socket))
            else:
                value = state.load()
                asyncio.run(contributor_client.rotate(state, value))
                result = {"node_id": value["node_id"], "rotated": True}
        print(json.dumps(result))
        return
    from .cli import local_request
    from .local_client import client
    request = {"action": "token", "label": "Contributor administration", "lifetime": 60,
               "scopes": ["contributors:read", "contributors:manage"]}
    if args.project:
        request["project_id"] = args.project
    grant = local_request(args.state_dir, request)
    fd = None
    try:
        if args.command == "contributor-invite":
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with client(grant, args.state_dir) as http:
            if args.command == "contributor-list":
                response = http.get("/api/v1/contributors")
            elif args.command == "contributor-invite":
                response = http.post("/api/v1/contributor-invitations", json={"name": args.name, "mode": args.mode})
            elif args.command == "contributor-approve":
                response = http.post(f"/api/v1/contributor-requests/{args.id}/approve", json={"public_key": args.public_key, "revision": args.revision})
            else:
                action = "remove" if args.command == "contributor-remove" else "disable"
                response = http.post(f"/api/v1/contributors/{args.id}/{action}", json={"revision": args.revision})
            response.raise_for_status()
            result = response.json()
        if fd is not None:
            with os.fdopen(fd, "w") as stream:
                fd = None
                stream.write(json.dumps(result, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            result = {"node_id": result["node_id"], "expires_at": result["expires_at"], "invitation_file": str(args.output)}
        print(json.dumps(result, indent=2))
    finally:
        if fd is not None:
            os.close(fd)
            args.output.unlink(missing_ok=True)
        local_request(args.state_dir, {"action": "revoke", "id": grant["id"]})
