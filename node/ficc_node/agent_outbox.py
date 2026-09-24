# SPDX-License-Identifier: Apache-2.0
"""Retain permanent host refusals separately from successful outbox storage."""

import hashlib
import json
import os

from . import agent_spool as spool


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":")).encode()).hexdigest()


def acknowledge(folder, acknowledgement):
    if isinstance(acknowledgement, str):
        identity = spool.identity(acknowledgement)
        path = folder / ("outbox-" + identity + ".json")
        if path.exists():
            spool.write(folder / ("sent-" + identity + ".json"), {"id": identity, "message": spool.read(path)})
            path.unlink()
            spool.sync(folder)
        return
    expected = {"id", "state", "code", "detail", "rejected_at", "sha256"}
    if not isinstance(acknowledgement, dict) or set(acknowledgement) != expected or acknowledgement["state"] != "host-rejected":
        raise ValueError("Invalid outbox acknowledgement.")
    identity = spool.identity(acknowledgement["id"])
    if any(not isinstance(acknowledgement[k], str) or len(acknowledgement[k]) > limit for k, limit in (("code", 80), ("detail", 240), ("sha256", 64))):
        raise ValueError("Invalid outbox rejection fields.")
    path, retained = folder / ("outbox-" + identity + ".json"), folder / ("rejected-" + identity + ".json")
    source = path if path.exists() else retained
    if digest(spool.read(source)) != acknowledgement["sha256"]:
        raise ValueError("The rejection does not match the pending outbox content.")
    receipt = folder / ("rejection-" + identity + ".json")
    if not receipt.exists():
        spool.write(receipt, acknowledgement)
    if path.exists():
        if retained.exists():
            if spool.read(retained) != spool.read(path):
                raise ValueError("The retained rejection content conflicts.")
            path.unlink()
        else:
            os.replace(path, retained)
    spool.sync(folder)


def inspect(folder, identity):
    identity = spool.identity(identity)
    return {"rejection": spool.read(folder / ("rejection-" + identity + ".json")),
            "message": spool.read(folder / ("rejected-" + identity + ".json"))}
