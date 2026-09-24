# SPDX-License-Identifier: Apache-2.0
"""Reject locally decidable bus-body errors before outbox publication."""

import json
import math

FIELDS = {
    "finding": ({"claim", "provenance"}, {"id", "claim", "provenance", "evidence", "refs", "confidence"}),
    "rank": ({"re", "score", "basis"}, {"re", "score", "basis"}),
    "question": ({"text"}, {"to", "re", "text"}), "answer": ({"re", "text"}, {"re", "text"}),
    "handoff": ({"path", "status"}, {"path", "status", "note"}),
    "note": ({"text"}, {"text"}), "cost": ({"consumed", "produced"}, {"consumed", "produced"}),
}


def validate(kind, body):
    if not isinstance(kind, str) or kind not in FIELDS or not isinstance(body, dict):
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
    if kind == "finding" and body["provenance"] not in {"computed", "fetched", "recalled", "testimony"}:
        raise ValueError("The finding provenance is invalid.")
    if kind == "handoff" and body["status"] not in {"draft", "ready", "blocked"}:
        raise ValueError("The handoff status is invalid.")
