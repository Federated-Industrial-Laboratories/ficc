# SPDX-License-Identifier: Apache-2.0
"""Validate the portable version-one bus envelope without executing its content."""

import json
import math
import re

TYPES = {"finding", "rank", "question", "answer", "handoff", "note", "cost"}
FIELDS = {
    "finding": ({"claim", "provenance"}, {"id", "claim", "provenance", "evidence", "refs", "confidence"}),
    "rank": ({"re", "score", "basis"}, {"re", "score", "basis"}),
    "question": ({"text"}, {"to", "re", "text"}),
    "answer": ({"re", "text"}, {"re", "text"}),
    "handoff": ({"path", "status"}, {"path", "status", "note"}),
    "note": ({"text"}, {"text"}), "cost": ({"consumed", "produced"}, {"consumed", "produced"}),
}


def validate(kind, body, message_id, previous):
    if kind not in TYPES or not isinstance(body, dict):
        raise ValueError("The bus message type or body is invalid.")
    required, allowed = FIELDS[kind]
    if not required <= set(body) or set(body) - allowed:
        raise ValueError("The bus message fields are invalid or unsupported.")
    if len(json.dumps(body, ensure_ascii=False, allow_nan=False).encode()) > 8192:
        raise ValueError("The bus message exceeds 8192 UTF-8 bytes.")
    for name, value in body.items():
        if name in {"score", "confidence"}:
            if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("The bus score is invalid.")
        elif name == "refs":
            if not isinstance(value, list) or len(value) > 32 or any(not isinstance(v, str) or len(v) > 2048 for v in value):
                raise ValueError("The bus references are invalid.")
        elif not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("The bus text is invalid.")
    result = dict(body)
    if kind == "finding":
        if body["provenance"] not in {"computed", "fetched", "recalled", "testimony"} or body.get("id", message_id) != message_id:
            raise ValueError("The finding identity or provenance is invalid.")
        result["id"] = message_id
    if kind == "handoff" and body["status"] not in {"draft", "ready", "blocked"}:
        raise ValueError("The handoff status is invalid.")
    if "re" in body:
        target = previous.get(body["re"])
        if target is None or (kind == "rank" and target["type"] not in {"finding", "handoff"}):
            raise ValueError("The bus reference does not identify an earlier permitted message.")
    return result


def envelope(value):
    from datetime import datetime, timezone
    return {"v": 1, "run": value["run_name"], "agent": value["sender_id"],
            "seq": value["sequence"], "ts": datetime.fromtimestamp(value["created_at"], timezone.utc).isoformat(),
            "type": value["type"], "body": value["body"]}


def portable(lines):
    previous: dict[str, dict] = {}
    sequences: dict[str, int] = {}
    run, result = None, []
    for raw in lines:
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) - {"v", "run", "agent", "seq", "ts", "type", "body"}:
            raise ValueError("The bus envelope contains unsupported fields.")
        if value.get("v") != 1 or not isinstance(value.get("run"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value["run"]):
            raise ValueError("The bus run envelope is invalid.")
        if run is not None and run != value["run"]:
            raise ValueError("A bus file must contain one run.")
        run = value["run"]
        sender, sequence = value.get("agent"), value.get("seq")
        if not isinstance(sender, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", sender):
            raise ValueError("The bus sender is invalid.")
        if type(sequence) is not int or sequence != sequences.get(sender, 0) + 1:
            raise ValueError("Bus sequences must start at one and increase without gaps.")
        identity = f"{sender}-{sequence}"
        value["body"] = validate(value["type"], value["body"], identity, previous)
        sequences[sender], previous[identity] = sequence, value
        result.append(value)
        if len(result) > 16384:
            raise ValueError("The imported run exceeds capacity.")
    if not result:
        raise ValueError("The selected bus file has no messages.")
    return result
