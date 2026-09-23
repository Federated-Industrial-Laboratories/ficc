# SPDX-License-Identifier: Apache-2.0
"""Access typed job previews, submissions, results, logs and cancellation."""

import argparse
import base64
import json
import sys
import time
from contextlib import suppress
from pathlib import Path

import httpx

from .settings import default_state_dir


def add_commands(commands) -> None:
    for name in ("job-preview", "job-submit", "job-list", "job-status", "job-logs",
                 "job-cancel", "helper-upgrade"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name in {"job-preview", "job-submit"}:
            item.add_argument("--request", type=Path, required=True,
                              help="JSON file with action, node_ids and job fields.")
        if name == "job-submit":
            item.add_argument("--confirm", action="store_true",
                              help="Authorize the exact request and its frozen node list.")
            item.add_argument("--idempotency-key", default=None)
        if name in {"job-status", "job-logs", "job-cancel"}:
            item.add_argument("id", help="Operation ID.")
        if name == "job-logs":
            item.add_argument("--node", required=True)
            item.add_argument("--stream", choices=["stdout", "stderr"], default="stdout")
            item.add_argument("--offset", type=int, default=0)
            item.add_argument("--limit", type=int, default=65536)
            item.add_argument("--output", type=Path,
                              help="Create a private raw-output file; default prints JSON with base64 data.")
        if name == "job-cancel":
            item.add_argument("--node", action="append", required=True)
            item.add_argument("--force", action="store_true")
        if name == "helper-upgrade":
            item.add_argument("--node", required=True)
            item.add_argument("--fingerprint", required=True)


def reply(response: httpx.Response) -> dict:
    if response.is_error:
        try:
            message = response.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            message = "The job API request failed."
        raise ValueError(message)
    return response.json()


def request_file(path: Path) -> dict:
    with path.open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("The job request file exceeds 64 KiB.")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("The job request must be a JSON object.")
    return value


def submit(client: httpx.Client, args: argparse.Namespace, request: dict) -> dict:
    preview = reply(client.post("/api/v1/operation-previews", json=request))
    if args.command == "job-preview" or not args.confirm:
        return {"preview": preview, "submitted": False}
    raise ValueError("Confirmed submission requires a saved CLI receipt.")


def execute(args) -> None:
    from .cli import local_request

    request = request_file(args.request) if args.command in {"job-preview", "job-submit"} else None
    if args.command == "job-submit" and args.confirm:
        from .job_cli_state import submit_saved
        assert request is not None
        print(json.dumps(submit_saved(args, request), indent=2))
        return
    cancelling = args.command == "job-cancel"
    grant = local_request(args.state_dir, {"action": "job-credential" if cancelling else "ephemeral"})
    revoke = not cancelling
    try:
        with httpx.Client(base_url=grant["origin"], headers={"Authorization": "Bearer " + grant["credential"]},
                          timeout=90, trust_env=False) as client:
            if request is not None:
                result = submit(client, args, request)
            elif args.command == "job-list":
                result = reply(client.get("/api/v1/operations"))
            elif args.command == "job-status":
                result = reply(client.get("/api/v1/operations/" + args.id))
            elif args.command == "job-cancel":
                result = reply(client.post("/api/v1/operations/" + args.id + "/cancel",
                                           json={"node_ids": args.node, "force": args.force}))
                deadline = time.monotonic() + 10
                while True:
                    selected = [target for target in result["targets"] if target["node_id"] in args.node]
                    revoke = bool(selected) and all(target["state"] in
                        {"succeeded", "failed", "cancelled", "interrupted"} for target in selected)
                    if revoke or time.monotonic() >= deadline:
                        break
                    time.sleep(0.25)
                    result = reply(client.get("/api/v1/operations/" + args.id))
            elif args.command == "helper-upgrade":
                result = reply(client.post("/api/v1/nodes/" + args.node + "/helper-upgrade",
                                           json={"expected_fingerprint": args.fingerprint}))
            else:
                result = reply(client.get("/api/v1/operations/" + args.id + "/logs/" + args.node,
                                          params={"stream": args.stream, "offset": args.offset, "limit": args.limit}))
                if args.output:
                    import os
                    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(base64.b64decode(result.pop("data_base64"), validate=True))
                    result["output"] = str(args.output)
            print(json.dumps(result, indent=2))
    finally:
        if revoke:
            with suppress(OSError, ValueError):
                local_request(args.state_dir, {"action": "revoke", "id": grant["id"]})
        else:
            print(json.dumps({"cancellation_credential_id": grant["id"], "expires_at": grant["expires_at"],
                              "note": "Pending cancellation retains this credential until expiry; it remains revocable in Access."}),
                  file=sys.stderr)
