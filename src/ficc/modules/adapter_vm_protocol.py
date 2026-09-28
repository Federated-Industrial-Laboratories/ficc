# SPDX-License-Identifier: Apache-2.0
"""Validate provider VM data before it reaches host state or a workspace table."""

import hashlib

from . import adapter_protocol as spec
from .validation import digest, dumps, fields, identifier, invalid


def resource_id(key, birth):
    spec.plain(key)
    digest(birth)
    return hashlib.sha256(dumps({"key": key, "birth": birth})).hexdigest()[:32]


def error(value):
    fields(value, {"code", "message"})
    identifier(value["code"])
    spec.plain(value["message"], 256)
    return value


def receipt(value):
    fields(value, {"state", "token", "completed", "result"}, {"task_state"})
    if (value["state"] not in ("accepted", "observed", "failed", "unknown", "refused")
            or type(value["completed"]) is not bool or value["result"] not in ("success", "failure", "unknown")):
        raise invalid("Invalid provider receipt state.")
    spec.private(value["token"])
    if len(dumps(value["token"])) > 4096:
        raise invalid("The provider receipt token exceeds its limit.")
    if value["state"] == "accepted" and (value["completed"] or not value["token"]):
        raise invalid("An accepted provider receipt requires an unfinished task token.")
    if value["state"] in {"observed", "failed"} and (not value["completed"]
            or value["result"] != ("success" if value["state"] == "observed" else "failure")):
        raise invalid("The provider completion proof does not match its outcome.")
    if value["state"] == "refused" and (value["token"] or not value["completed"] or value["result"] != "failure"):
        raise invalid("A refused action must establish that dispatch did not occur.")
    task = value.get("task_state")
    if "task_state" in value and (task not in ("none", "active", "unknown", "finished")
            or task in {"active", "unknown"} and (value["completed"] or not value["token"])
            or task == "finished" and not value["completed"]):
        raise invalid("The provider task ownership does not match its completion proof.")
    return value


def pending_task(value):
    """An omitted task class conservatively retains every unfinished task token."""
    return bool(value and value["token"] and not value["completed"]
                and value.get("task_state", "active") in {"active", "unknown"})


def row(value):
    fields(value, {"resource", "name", "memory_kib", "vcpus", "console"})
    resource = spec.resource(value["resource"])
    if resource["id"] != resource_id(resource["key"], resource["birth"]):
        raise invalid("The VM identity does not match its stable provider key and birth.")
    spec.plain(value["name"], 256)
    spec.integer(value["memory_kib"], 0, 2**53 - 1)
    spec.integer(value["vcpus"], 0, 65536)
    if type(value["console"]) is not bool:
        raise invalid("The VM console state is invalid.")
    return value


def result(value, phase, action, binding):
    """Require a complete ordered resource batch and bounded phase-specific data."""
    if phase == "probe":
        fields(value, {"provider"})
        fields(value["provider"], {"name", "version", "fingerprint"})
        spec.plain(value["provider"]["name"], 160)
        spec.plain(value["provider"]["version"], 160)
        digest(value["provider"]["fingerprint"])
        return value
    if phase == "inventory":
        fields(value, {"resources", "next_offset", "truncated"})
        items = value["resources"]
        limit = binding["parameters"].get("limit", 64)
        if not isinstance(items, list) or len(items) > spec.integer(limit, 1, 256):
            raise invalid("The VM inventory exceeds its requested row limit.")
        ids = [row(item)["resource"]["id"] for item in items]
        if len(set(ids)) != len(ids) or type(value["truncated"]) is not bool:
            raise invalid("The VM inventory repeats an identity or has invalid pagination.")
        offset = binding["parameters"].get("offset", 0)
        if value["next_offset"] is not None:
            spec.integer(value["next_offset"], spec.integer(offset, 0, 4096) + 1, 4096)
        if value["truncated"] != (value["next_offset"] is not None):
            raise invalid("The VM inventory continuation does not match its truncated state.")
        return value
    if phase == "console":
        fields(value, {"resource", "kind", "binding_id", "parameters"})
        resource = spec.resource(value["resource"])
        if len(binding["resources"]) != 1 or resource != binding["resources"][0]:
            raise invalid("The console resource changed after selection.")
        if value["kind"] not in {"vnc", "vmconnect"}:
            raise invalid("The provider console transport is unsupported.")
        spec.identity(value["binding_id"])
        spec.private(value["parameters"])
        return value
    fields(value, {"results"})
    rows, selected = value["results"], binding["resources"]
    if not isinstance(rows, list) or len(rows) != len(selected):
        raise invalid("The VM response must complete every requested resource.")
    for item, resource in zip(rows, selected, strict=True):
        spec.identity(item.get("id") if isinstance(item, dict) else None)
        if item["id"] != resource["id"]:
            raise invalid("The VM response resource identity or order changed.")
        if phase in {"apply", "observe"}:
            fields(item, {"id", "receipt"}, {"observed_state", "error"})
            receipt(item["receipt"])
            if "observed_state" in item and item["observed_state"] not in spec.STATES:
                raise invalid("The observed VM state is invalid.")
            if "error" in item:
                error(item["error"])
            continue
        keys = {"data"} if phase == "status" else {"intent", "desired_state"}
        fields(item, {"id"}, keys | {"error"})
        if "error" in item:
            if set(item) != {"id", "error"}:
                raise invalid("A refused VM resource cannot also contain data.")
            error(item["error"])
        elif phase == "status":
            fields(item, {"id", "data"})
            current = row(item["data"])["resource"]
            if any(current[key] != resource[key] for key in ("id", "key", "birth")):
                raise invalid("The provider VM birth identity changed.")
        else:
            fields(item, {"id", "intent", "desired_state"})
            spec.private(item["intent"])
            if len(dumps(item["intent"])) > 4096 or item["desired_state"] != {"start": "running", "shutdown": "off"}[action]:
                raise invalid("The private VM intent or desired state is invalid.")
    return value
