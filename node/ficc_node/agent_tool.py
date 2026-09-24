# SPDX-License-Identifier: Apache-2.0
"""Read a registered local inbox or submit an explicitly addressed bus reply."""

import argparse
import json
import os
import secrets
import sys

from . import agent_spool as spool
from .agent_message import validate


def operate(controller, agent, action, request):
    with spool.locked(controller, agent) as folder:
        spec = spool.read(folder / "spec.json")
        if spec["agent_id"] != agent or spec["controller_id"] != controller:
            raise ValueError("The local agent binding changed.")
        if action == "rejects":
            after = request.get("after")
            if after is not None:
                spool.identity(after)
            paths = [p for p in sorted(folder.glob("rejection-*.json")) if after is None or p.name[10:-5] > after]
            return {"rejections": [spool.read(p) for p in paths[:8]],
                    "next_after": paths[7].name[10:-5] if len(paths) > 8 else None}
        if action == "rejected":
            from .agent_outbox import inspect
            return inspect(folder, request["idempotency_key"])
        if action == "list":
            after = request.get("after")
            if after is not None:
                spool.identity(after)
            paths = [path for path in sorted(folder.glob("inbox-*.json")) if after is None or path.name[6:-5] > after]
            selected = paths[:8]
            return {"messages": [spool.read(path) for path in selected],
                    "next_after": selected[-1].name[6:-5] if len(paths) > 8 else None}
        if action == "read":
            delivery = spool.identity(request["delivery_id"])
            value = spool.read(folder / ("inbox-" + delivery + ".json"))
            current = spool.read(folder / ("receipt-" + delivery + ".json"))
            if value["method"] != "direct" or current["state"] not in {"uncertain", "adapter-submitted"}:
                spool.receipt(folder, delivery, "tool-read", "Read through the registered local inbox tool.")
            return value
        if action != "send" or set(request) != {"type", "body", "recipient_ids", "reply_to", "idempotency_key", "delivery"}:
            raise ValueError("Invalid local bus action.")
        validate(request["type"], request["body"])
        if len(json.dumps(request, ensure_ascii=False).encode()) > 12288:
            raise ValueError("The outbox message exceeds capacity.")
        if request["delivery"] not in {"inbox", "direct"}:
            raise ValueError("Select inbox or direct delivery.")
        key = spool.identity(request["idempotency_key"])
        targets = request["recipient_ids"]
        if not isinstance(targets, list) or len(targets) > 64 or len(set(targets)) != len(targets):
            raise ValueError("Select at most 64 distinct enrolled recipients.")
        for target in targets:
            spool.identity(target)
        if request["reply_to"] is not None:
            spool.identity(request["reply_to"])
        path = folder / ("outbox-" + key + ".json")
        value = {"id": key, **request}
        rejected = folder / ("rejected-" + key + ".json")
        if rejected.exists():
            if spool.read(rejected) != value:
                raise ValueError("The outbox key already identifies different rejected content.")
            return spool.read(folder / ("rejection-" + key + ".json"))
        sent = folder / ("sent-" + key + ".json")
        if sent.exists():
            if spool.read(sent).get("message") != value:
                raise ValueError("The outbox key already identifies different acknowledged content.")
            return {"id": key, "state": "host-stored"}
        if path.exists():
            if spool.read(path) != value:
                raise ValueError("The outbox key already identifies different content.")
        else:
            if len(list(folder.glob("outbox-*.json"))) >= 128:
                raise ValueError("The pending outbox is full.")
            spool.write(path, value)
        return {"id": key, "state": "node-stored"}


def main(argv):
    parser = argparse.ArgumentParser(description="Read the FICC inbox or submit a bus reply.")
    sub = parser.add_subparsers(dest="action", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("--after")
    listing = sub.add_parser("rejects")
    listing.add_argument("--after")
    item = sub.add_parser("rejected")
    item.add_argument("idempotency_key")
    item = sub.add_parser("read")
    item.add_argument("delivery_id")
    item = sub.add_parser("send")
    item.add_argument("--recipient", action="append", default=[])
    item.add_argument("--reply-to")
    item.add_argument("--idempotency-key", default=None)
    item.add_argument("--type", default="note")
    item.add_argument("--delivery", choices=("inbox", "direct"), default="inbox")
    args = parser.parse_args(argv)
    request = vars(args)
    action = request.pop("action")
    if action == "send":
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise ValueError("The bus body exceeds capacity.")
        request = {"type": args.type, "body": json.loads(raw), "recipient_ids": args.recipient,
                   "reply_to": args.reply_to, "delivery": args.delivery, "idempotency_key": args.idempotency_key or secrets.token_hex(16)}
    result = operate(os.environ["FICC_CONTROLLER_ID"], os.environ["FICC_AGENT_ID"], action, request)
    print(json.dumps(result, allow_nan=False))
    return 0
