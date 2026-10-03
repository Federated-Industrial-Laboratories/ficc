# SPDX-License-Identifier: Apache-2.0
"""Persist one audit stream checkpoint without holding the controller database lock."""

import json
import re
import time
from pathlib import Path

from . import secret_io
from .audit_sdk import MAX_BATCH, AuditError, batch, encoded, identity
from .secret_sdk import reference

PRIVATE = "audit-private"
CONFIG = "configuration.json"
CHECKPOINT = "checkpoint.json"
REQUIRED = "audit_delivery_required"


def configuration(raw):
    try:
        value = json.loads(raw)
        if (set(value) != {"provider", "configuration", "secret_reference", "required", "max_lag_events", "stream_id"}
                or not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", value["provider"])
                or not isinstance(value["configuration"], dict) or type(value["required"]) is not bool
                or type(value["max_lag_events"]) is not int or not 1 <= value["max_lag_events"] <= 10000
                or not re.fullmatch(r"[a-f0-9]{32}", value["stream_id"])):
            raise ValueError()
        reference(value["secret_reference"])
        return value
    except (ValueError, TypeError, KeyError):
        raise AuditError("audit_configuration") from None


def initial(stream):
    return {"stream_id": stream, "sequence": 0, "cursor": 0, "last_seen": 0,
            "last_ack_at": None, "gap_events": 0, "pending": None}


class State:
    def __init__(self, state, config):
        self.path = Path(state) / PRIVATE
        with secret_io.directory(self.path) as folder:
            raw = secret_io.read(folder, CHECKPOINT, MAX_BATCH + 4096)
        try:
            value = json.loads(raw)
            if (set(value) != set(initial(config["stream_id"])) or value["stream_id"] != config["stream_id"]
                    or any(type(value[key]) is not int or not 0 <= value[key] < 2**63
                           for key in ("sequence", "cursor", "last_seen", "gap_events"))
                    or value["last_seen"] < value["cursor"]
                    or value["last_ack_at"] is not None and (type(value["last_ack_at"]) not in {int, float}
                                                           or not 0 <= value["last_ack_at"] <= time.time() + 300)):
                raise ValueError()
            if value["pending"] is not None:
                pending = batch(encoded(value["pending"]))
                if (pending["stream_id"] != value["stream_id"] or pending["sequence"] != value["sequence"] + 1
                        or pending["after"] != value["cursor"]):
                    raise ValueError()
            self.value = value
        except (ValueError, TypeError, KeyError):
            raise AuditError("audit_configuration") from None

    def save(self, value):
        with secret_io.directory(self.path) as folder:
            secret_io.publish(folder, CHECKPOINT, encoded(value), replace=True)


def page(store, cursor):
    with store.lock:
        last = store.db.execute("SELECT max(id) FROM audit").fetchone()[0] or 0
        rows = store.db.execute("SELECT id,at,action,target,outcome,actor,subject_id,project_id FROM audit "
                                "WHERE id>:p0 ORDER BY id LIMIT 64", (cursor,)).fetchall()
    events = []
    for number, at, action, target, outcome, actor, subject, project in rows:
        if number > cursor + 1:
            events.append({"kind": "retention_gap", "first_id": cursor + 1, "last_id": number - 1})
        events.append({"kind": "event", "id": number, "at": at,
            "action": action if re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", action) else "other",
            "outcome": outcome if outcome in {"success", "failed", "unknown", "requested", "queued", "running",
                "starting", "preparing", "prepared", "completed", "succeeded", "cancelled", "expired", "denied",
                "confirmed", "accepted", "approved", "enabled", "disabled", "registered", "verified"} else "other",
            "outcome_sha256": identity(outcome), "target_sha256": identity(target), "actor_sha256": identity(actor),
            "subject_sha256": identity(subject), "project_sha256": identity(project)})
        cursor = number
    return last, cursor, events
