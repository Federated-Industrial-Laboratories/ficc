# SPDX-License-Identifier: Apache-2.0
"""Request exact idempotent node archives through the pinned SSH helper."""

import json
import re

from .errors import Failure
from .ssh import PROBE, SSH


async def archive(transport: SSH, node, intent):
    request = {"version": "3", "action": "history.archive", **{key: intent[key] for key in
               ("archive_id", "controller_id", "terminal_controller", "next_controller_id", "next_terminal_controller")}}
    try:
        code, raw, _ = await transport.command(node, PROBE, json.dumps(request).encode() + b"\n", timeout=360)
    except Failure as exc:
        raise ValueError("Node archival is unfinished. Restore connectivity and resume the same command: " + exc.message) from None
    try:
        value = json.loads(raw)
        if code or value.get("version") != "3":
            raise ValueError()
        result = value["result"]
        fields = {"archive_id", "state", "path", "manifest_sha256", "members", "bytes", "controller_id", "next_controller_id"}
        if (set(result) != fields or result["state"] != "complete" or result["archive_id"] != intent["archive_id"]
                or result["controller_id"] != intent["controller_id"] or result["next_controller_id"] != intent["next_controller_id"]
                or not isinstance(result["path"], str) or not result["path"].startswith("/") or len(result["path"]) > 4096
                or not isinstance(result["manifest_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", result["manifest_sha256"])
                or type(result["members"]) is not int or not 0 <= result["members"] <= 8192
                or type(result["bytes"]) is not int or not 0 <= result["bytes"] <= 4 * 1024**3):
            raise ValueError()
        return result
    except (ValueError, KeyError, TypeError):
        raise ValueError("The node did not confirm history archival. Check its helper, closed receipts and exact systemd/tmux state, then resume.") from None
