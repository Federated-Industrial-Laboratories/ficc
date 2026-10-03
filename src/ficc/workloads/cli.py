# SPDX-License-Identifier: Apache-2.0
"""Configure an installed scheduler and operate project jobs through the local owner socket."""

import json
from pathlib import Path

from ..launcher_config import write_file
from ..settings import default_state_dir, private_directory
from ..state_lock import StateLock
from ..state_provider import read_private
from .provider import Configuration, load
from .routes import Batch


def add_commands(commands):
    for name in ("workloads-configure", "workload-list", "workload-offers", "workload-submit", "workload-get",
                 "workload-cancel", "workload-retry", "workload-release", "workload-remove", "workload-abandon"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name == "workloads-configure":
            item.add_argument("--input", type=Path, required=True)
            continue
        item.add_argument("--project")
        if name == "workload-submit":
            item.add_argument("--input", type=Path, required=True)
        elif name not in {"workload-list", "workload-offers"}:
            item.add_argument("id")
            if name != "workload-get":
                item.add_argument("--revision", type=int, required=True)
            if name in {"workload-retry", "workload-abandon"}:
                item.add_argument("--acknowledge-unknown", action="store_true")
            if name in {"workload-release", "workload-remove", "workload-abandon"}:
                item.add_argument("--confirm", action="store_true", required=True)


def configure(state, source):
    private_directory(state)
    configuration = Configuration.model_validate_json(read_private(source))
    with StateLock(state):
        path = state / "workload-provider.json"
        previous = read_private(path) if path.exists() or path.is_symlink() else None
        try:
            write_file(path, configuration.model_dump_json() + "\n")
            provider = load(state)
            assert provider is not None
            provider.close()
        except BaseException:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                write_file(path, previous.decode())
            raise
    return {"configured": True, "restart_required": True}


def execute(args):
    if args.command == "workloads-configure":
        print(json.dumps(configure(args.state_dir, args.input)))
        return
    from ..cli import local_request
    from ..local_client import client
    action = args.command.removeprefix("workload-")
    scope = "contributors:read" if action == "offers" else "jobs:execute" if action in {"submit", "retry"} else (
        "jobs:cancel" if action in {"cancel", "release", "remove", "abandon"} else "jobs:read")
    scopes = {scope, "contributors:read"}
    if action == "abandon":
        scopes.add("contributors:manage")
    request = {"action": "token", "label": "Contributor workloads", "lifetime": 60,
               "scopes": sorted(scopes)}
    if args.project:
        request["project_id"] = args.project
    body = None
    if action == "submit":
        body = Batch.model_validate_json(read_private(args.input, 8 * 1024 * 1024)).model_dump()
    elif action in {"cancel", "retry", "release", "remove", "abandon"}:
        body = {"revision": args.revision}
        if action in {"retry", "abandon"}:
            body["acknowledge_unknown"] = args.acknowledge_unknown
    grant = local_request(args.state_dir, request)
    try:
        with client(grant, args.state_dir) as http:
            if action in {"list", "offers", "get"}:
                path = "/workload-offers" if action == "offers" else "/workloads" + ("/" + args.id if action == "get" else "")
                response = http.get("/api/v1" + path)
            else:
                path = "/workloads" + ("/" + args.id + "/" + action if action != "submit" else "")
                response = http.post("/api/v1" + path, json=body)
            response.raise_for_status()
            print(json.dumps(response.json(), indent=2))
    finally:
        local_request(args.state_dir, {"action": "revoke", "id": grant["id"]})
