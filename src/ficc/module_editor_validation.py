# SPDX-License-Identifier: Apache-2.0
"""Validate bounded editor history and retained recovery before state export."""

import base64
import hashlib
import hmac
import json
import math
import re
import stat

from ficc_node.file_access import parts

MAX_RECORD = 4 * 1024 * 1024
FIELDS = set("workspace_id instance_id package_digest targets module_revision id actor key request_digest created_at updated_at state items".split())
ITEM_FIELDS = set("id root_id root entry_id reference expected_sha256 submitted_sha256 state retained resolved receipt".split())
STATES = {"pending", "unknown", "succeeded", "failed", "conflict"}


def need(condition):
    if not condition:
        raise ValueError("An editor receipt is invalid or exceeds its limit.")


def identifier(value, length=32):
    need(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{%d}" % length, value) is not None)


def text(value, maximum, empty=False):
    need(isinstance(value, str) and (empty or bool(value)) and len(value.encode("utf-8")) <= maximum and "\0" not in value)


def exact(value, required, optional=frozenset()):
    need(isinstance(value, dict) and required <= value.keys() and not value.keys() - required - optional)


def number(value, lower=0):
    need(type(value) in {int, float} and math.isfinite(value) and value >= lower)


def identity(value, kind):
    exact(value, set("dev ino type size mtime_ns ctime_ns".split()))
    need(all(type(item) is int and abs(item) < 2**128 for item in value.values()))
    need(value["dev"] >= 0 and value["ino"] > 0 and value["size"] >= 0 and value["type"] == kind)


def reference(value, directory=False):
    exact(value, {"parts", "identity"}, {"parent"})
    path = parts(value)
    need(not directory or not path)
    identity(value["identity"], stat.S_IFDIR if directory else stat.S_IFREG)
    if path:
        need("parent" in value)
        identity(value["parent"], stat.S_IFDIR)
    else:
        need(directory and "parent" not in value)


def root(value):
    exact(value, set("id path label node_id read_only revision identity reference mode_supported".split()), {"fingerprint"})
    identifier(value["id"])
    identifier(value["revision"])
    text(value["path"], 4096)
    need(value["path"].startswith("/"))
    text(value["label"], 320)
    need(type(value["read_only"]) is bool and type(value["mode_supported"]) is bool)
    if value["node_id"] is not None:
        identifier(value["node_id"])
        text(value.get("fingerprint"), 256)
    else:
        need("fingerprint" not in value)
    identity(value["identity"], stat.S_IFDIR)
    reference(value["reference"], directory=True)
    need(value["reference"]["identity"] == value["identity"])


def error(value):
    if value is not None:
        exact(value, {"code", "message"})
        text(value["code"], 80)
        text(value["message"], 1024, empty=True)


def item(value, targets, signing_key):
    exact(value, ITEM_FIELDS, {"error", "message"})
    identifier(value["id"])
    identifier(value["root_id"])
    need(value["root_id"] in targets)
    root(value["root"])
    need(value["root_id"] == value["root"]["id"])
    reference(value["reference"])
    text(value["entry_id"], 16384)
    raw = base64.b64decode(value["entry_id"] + "=" * (-len(value["entry_id"]) % 4), altchars=b"-_", validate=True)
    need(hmac.compare_digest(hmac.digest(signing_key, raw[:-32], hashlib.sha256), raw[-32:]))
    need(json.loads(raw[:-32]) == {"root": value["root_id"], "revision": value["root"]["revision"], "entry": value["reference"]})
    for key in ("expected_sha256", "submitted_sha256"):
        identifier(value[key], 64)
    need(value["state"] in STATES and type(value["retained"]) is bool and type(value["resolved"]) is bool)
    if "message" in value:
        text(value["message"], 1024, empty=True)
    error(value.get("error"))
    receipt = value["receipt"]
    need(isinstance(receipt, dict))
    if receipt:
        exact(receipt, set("id state retained resolved message sha256 reference".split()))
        need(receipt["id"] == value["id"] and receipt["state"] in STATES | {"preparing"})
        need(("unknown" if receipt["state"] == "preparing" else receipt["state"]) == value["state"])
        need(type(receipt["retained"]) is bool and type(receipt["resolved"]) is bool)
        need(receipt["retained"] == value["retained"] and receipt["resolved"] == value["resolved"])
        need(receipt["sha256"] == value["submitted_sha256"])
        text(receipt["message"], 1024, empty=True)
        if receipt["reference"] is not None:
            reference(receipt["reference"])
            need(receipt["reference"]["parts"] == value["reference"]["parts"])
            need(all(receipt["reference"]["parent"][key] == value["reference"]["parent"][key]
                     for key in ("dev", "ino", "type")))
            need(receipt["reference"]["identity"]["dev"] == value["reference"]["identity"]["dev"])
        need(receipt["state"] != "succeeded" or receipt["reference"] is not None)
    else:
        need(value["state"] in {"pending", "unknown", "failed"})
    need(value["state"] != "pending" or not value["retained"])
    need(not value["resolved"] or value["state"] in {"succeeded", "failed", "conflict"})


def record(value, row, signing_key, quiescent):
    exact(value, FIELDS)
    for key in ("workspace_id", "instance_id", "id", "actor", "key"):
        identifier(value[key])
    for key in ("package_digest", "request_digest"):
        identifier(value[key], 64)
    need(tuple(value[key] for key in ("id", "actor", "key")) == row and value["id"] == value["key"])
    need(type(value["module_revision"]) is int and value["module_revision"] >= 1)
    targets = value["targets"]
    need(isinstance(targets, list) and 1 <= len(targets) <= 64)
    for target in targets:
        identifier(target)
    need(len(set(targets)) == len(targets))
    for key in ("created_at", "updated_at"):
        number(value[key])
    need(value["updated_at"] >= value["created_at"])
    items = value["items"]
    need(isinstance(items, list) and 1 <= len(items) <= 64)
    for entry in items:
        item(entry, targets, signing_key)
    need(len({entry["id"] for entry in items}) == len(items))
    need(len({(entry["root_id"], entry["entry_id"]) for entry in items}) == len(items))
    states = {entry["state"] for entry in items}
    expected = "unknown" if states & {"pending", "unknown"} else "conflict" if "conflict" in states else "failed" if "failed" in states else "succeeded"
    need(value["state"] == expected)
    if quiescent and (states & {"pending", "unknown", "conflict"} or any(entry["retained"] for entry in items)):
        raise ValueError("Resolve editor outcomes and remove retained copies and conflict receipts before backup or restore.")


def pairs(values):
    result = dict(values)
    need(len(result) == len(values))
    return result


def validate_records(db, *, quiescent=False):
    rows = db.execute("SELECT id,actor,key,value FROM module_editor_operations").fetchall()
    need(len(rows) <= 128)
    if not rows:
        return
    row = db.execute("SELECT value FROM settings WHERE key='file_reference_key'").fetchone()
    need(row is not None)
    key = json.loads(row[0])
    identifier(key, 64)
    for identity_value, actor, request_key, raw in rows:
        text(raw, MAX_RECORD)
        try:
            value = json.loads(raw, object_pairs_hook=pairs)
            record(value, (identity_value, actor, request_key), bytes.fromhex(key), quiescent)
        except (KeyError, TypeError, OverflowError, UnicodeError, RecursionError) as exc:
            raise ValueError("An editor receipt is invalid.") from exc
