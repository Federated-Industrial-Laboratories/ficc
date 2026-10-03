# SPDX-License-Identifier: Apache-2.0
"""Versioned append-only audit batches with exact, bounded durability acknowledgements."""

import hashlib
import importlib.metadata
import json
import re

API_VERSION = 1
MAX_BATCH = 65536
MAX_ACK = 1024
DELIVERY_SECONDS = 5
ERRORS = {
    "audit_unavailable": "The durable audit destination is unavailable. No protected mutation was admitted.",
    "audit_configuration": "Configure a valid private audit destination while the controller is stopped.",
    "audit_provider": "Install exactly one compatible trusted audit provider package.",
    "audit_acknowledgement": "The audit destination did not acknowledge this exact batch as durable.",
    "audit_backpressure": "Audit delivery is behind or its admission queue is full. Retry after delivery recovers.",
    "audit_history": "Audit history moved behind its checkpoint. Reconcile the separate destination before reconfiguration.",
}


class AuditError(ValueError):
    def __init__(self, code="audit_unavailable"):
        self.code = code if code in ERRORS else "audit_unavailable"
        super().__init__(ERRORS[self.code])


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def identity(value):
    return hashlib.sha256(b"ficc-audit-identity\0" + str(value).encode()).hexdigest() if value is not None else None


def batch(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_BATCH:
        raise AuditError("audit_acknowledgement")
    try:
        value = json.loads(raw)
        if (set(value) != {"version", "stream_id", "sequence", "after", "through", "events"}
                or type(value["version"]) is not int or value["version"] != API_VERSION
                or not re.fullmatch(r"[a-f0-9]{32}", value["stream_id"])
                or any(type(value[key]) is not int or not 0 <= value[key] < 2**63
                       for key in ("sequence", "after", "through"))
                or value["sequence"] < 1 or value["through"] < value["after"]
                or not isinstance(value["events"], list) or not 1 <= len(value["events"]) <= 128
                or any(not isinstance(event, dict) for event in value["events"])
                or encoded(value) != raw):
            raise ValueError()
        return value
    except (ValueError, TypeError, KeyError):
        raise AuditError("audit_acknowledgement") from None


def acknowledgement(value, raw):
    requested = batch(raw)
    expected = {"version": API_VERSION, "stream_id": requested["stream_id"], "sequence": requested["sequence"],
                "sha256": hashlib.sha256(raw).hexdigest(), "durable": True}
    if encoded(value) != encoded(expected):
        raise AuditError("audit_acknowledgement")
    return expected


def load(name):
    try:
        matches = list(importlib.metadata.entry_points(group="ficc.audit", name=name))
        if len(matches) != 1:
            raise AuditError("audit_provider")
        module = matches[0].load()
        if module.API_VERSION != API_VERSION or not callable(module.configure):
            raise AuditError("audit_provider")
        return module
    except AuditError:
        raise
    except Exception:
        raise AuditError("audit_provider") from None
