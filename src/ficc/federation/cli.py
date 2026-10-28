# SPDX-License-Identifier: Apache-2.0
"""Operate federation with project credentials and explicit mutation identifiers."""
import json
import time
from pathlib import Path

from ..settings import default_state_dir


def add_commands(commands):
    for name in ("federation-status", "federation-configure", "federation-pair", "federation-approve",
                 "federation-finish", "federation-remove", "federation-grant", "federation-revoke",
                 "federation-refresh", "federation-request", "federation-acquire", "federation-pause",
                 "federation-retire", "federation-forget"):
        parser = commands.add_parser(name)
        parser.add_argument("--state-dir", type=Path, default=default_state_dir())
        parser.add_argument("--project")
        if name not in {"federation-status", "federation-configure", "federation-pair"}:
            parser.add_argument("id")
        if name in {"federation-configure", "federation-pair", "federation-approve", "federation-grant", "federation-request"}:
            parser.add_argument("--input", type=Path, required=True)
        if name == "federation-refresh":
            parser.add_argument("--grant")
        if name == "federation-acquire":
            parser.add_argument("--model", required=True)
        if name == "federation-request":
            parser.add_argument("--output", type=Path, help="Exclusive output file for a streaming response.")


def execute(args):
    from ..cli import local_request
    from ..local_client import client
    scopes = ["federation:read", "federation:manage", "federation:invoke", "models:read", "models:manage",
              "inference:read", "inference:manage", "inference:invoke", "jobs:execute", "jobs:cancel", "contributors:read"]
    token = {"action": "token", "label": "Federation operation", "lifetime": 3600, "scopes": scopes}
    if args.project:
        token["project_id"] = args.project
    grant = local_request(args.state_dir, token)
    action = args.command.removeprefix("federation-")
    body = json.loads(args.input.read_text()) if hasattr(args, "input") else None
    prefix = "/api/v1/federation"
    endpoint, method = {
        "status": ("", "GET"), "configure": ("/configuration", "PUT"), "pair": ("/offers", "POST"),
        "approve": (f"/offers/{getattr(args, 'id', '')}/approve", "POST"),
        "finish": (f"/offers/{getattr(args, 'id', '')}/finish", "POST"),
        "remove": (f"/peers/{getattr(args, 'id', '')}", "DELETE"),
        "grant": (f"/peers/{getattr(args, 'id', '')}/grants", "POST"),
        "revoke": (f"/grants/{getattr(args, 'id', '')}", "DELETE"),
        "refresh": (f"/peers/{getattr(args, 'id', '')}/refresh", "POST"),
        "request": (f"/peers/{getattr(args, 'id', '')}/request", "POST"),
        "acquire": (f"/peers/{getattr(args, 'id', '')}/models", "POST"),
        "pause": (f"/transfers/{getattr(args, 'id', '')}/pause", "POST"),
        "retire": (f"/grants/{getattr(args, 'id', '')}/retire", "POST"),
        "forget": (f"/peers/{getattr(args, 'id', '')}/forget", "POST"),
    }[action]
    if action == "refresh":
        body = {"grant": args.grant}
    if action == "acquire":
        body = {"model": args.model}
    try:
        with client(grant, args.state_dir) as http:
            if action == "request" and args.output:
                with http.stream(method, prefix+endpoint, json=body, timeout=3600) as response:
                    response.raise_for_status()
                    with args.output.open("xb") as output:
                        for data in response.iter_bytes(1024*1024):
                            output.write(data)
            else:
                response = http.request(method, prefix+endpoint, json=body, timeout=120)
                response.raise_for_status()
                if action == "acquire":
                    transfer = response.json()
                    deadline = time.monotonic()+3500
                    try:
                        while transfer["state"] not in {"complete", "paused", "interrupted"}:
                            if time.monotonic() >= deadline:
                                raise TimeoutError("The CLI transfer deadline expired; resume acquisition later.")
                            time.sleep(2)
                            status = http.get(prefix, timeout=30)
                            status.raise_for_status()
                            transfer = next(v for v in status.json()["transfers"] if v["id"] == transfer["id"])
                    except BaseException:
                        http.post(prefix+f"/transfers/{transfer['id']}/pause", timeout=30).raise_for_status()
                        raise
                    print(json.dumps(transfer, indent=2))
                    if transfer["state"] != "complete":
                        raise ValueError("The model transfer is incomplete; inspect its status and resume.")
                    return
                print(json.dumps(response.json(), indent=2))
    finally:
        local_request(args.state_dir, {"action": "revoke", "id": grant["id"]})
