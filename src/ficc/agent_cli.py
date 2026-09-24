# SPDX-License-Identifier: Apache-2.0
"""Register explicit installed agent profiles through the private owner socket."""

import json
from pathlib import Path

from .settings import default_state_dir


def add_commands(commands):
    for name in ("agent-profile-add", "agent-profile-list", "agent-profile-remove", "bus-export", "bus-import", "bus-archive"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name == "agent-profile-add":
            item.add_argument("--node", required=True)
            item.add_argument("--name", required=True)
            item.add_argument("--adapter", choices=("generic", "omp", "codex"), required=True)
            item.add_argument("--workspace", required=True)
            item.add_argument("--argv-json", required=True, help="Explicit executable and arguments as a JSON array.")
        elif name == "agent-profile-remove":
            item.add_argument("id")
        elif name == "bus-import":
            item.add_argument("--input", type=Path, required=True)
        elif name in {"bus-export", "bus-archive"}:
            item.add_argument("--run", required=True)
            item.add_argument("--output", type=Path, required=True)
            if name == "bus-archive":
                item.add_argument("--confirm", action="store_true")


def execute(args):
    if args.command == "bus-archive":
        from .cli import local_request
        for _ in range(65):
            result = local_request(args.state_dir, {"action": "bus-archive", "run": args.run,
                "output": str(args.output.absolute()), "confirm": args.confirm})
            if result["archived"]:
                print(json.dumps(result, indent=2))
                return
        raise ValueError("The archive remains incomplete. Resume with the same output directory.")
    if args.command.startswith("bus-"):
        from .bus_cli import execute as execute_bus
        execute_bus(args)
        return
    from .cli import local_request
    request = {"action": args.command}
    if args.command == "agent-profile-add":
        request["profile"] = {"node_id": args.node, "name": args.name, "adapter": args.adapter,
                              "workspace": args.workspace, "argv": json.loads(args.argv_json)}
    elif args.command == "agent-profile-remove":
        request["id"] = args.id
    print(json.dumps(local_request(args.state_dir, request), indent=2))
