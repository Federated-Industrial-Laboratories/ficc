# SPDX-License-Identifier: Apache-2.0
"""Register explicit file roots through the private local owner socket."""

import json
from pathlib import Path

from .settings import default_state_dir


def add_commands(commands):
    for name in ("root-add", "root-list", "root-remove"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name == "root-add":
            item.add_argument("--label", required=True)
            item.add_argument("--path", required=True)
            item.add_argument("--node")
            item.add_argument("--read-only", action="store_true")
        elif name == "root-remove":
            item.add_argument("id")


def execute(args):
    from .cli import local_request
    request = {"action": args.command}
    if args.command == "root-add":
        request.update(path=args.path, label=args.label, node_id=args.node, read_only=args.read_only)
    elif args.command == "root-remove":
        request["root_id"] = args.id
    print(json.dumps(local_request(args.state_dir, request), indent=2))
