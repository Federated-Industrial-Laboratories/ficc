# SPDX-License-Identifier: Apache-2.0
"""Retain node dispatch intent and never execute a repeated operation identity."""

import copy
import hashlib

from ficc.errors import Failure
from ficc.modules.adapter_protocol import identity
from ficc.modules.validation import digest, dumps, fields, loads

from .adapter_store import directory, read, sync, write


def location(base, profile_id, intent):
    fields(intent, {"controller", "operation", "digest", "targets"})
    identity(intent["controller"])
    identity(intent["operation"])
    digest(intent["digest"])
    identity(profile_id)
    return directory(base, "receipts") / (profile_id + "-" + intent["controller"] + "-" + intent["operation"] + ".json")


def unknown(resource):
    return {"id": resource["id"], "receipt": {"state": "unknown", "token": {},
            "completed": False, "result": "unknown"}, "error": {"code": "adapter_outcome_unknown",
            "message": "The provider outcome is unknown. This request will not be repeated."}}


def matching(saved, checksum, binding):
    if (saved["digest"] != checksum or saved["profile_id"] != binding["id"]
            or any(saved["intent"][name] != binding["intent"][name] for name in ("controller", "operation", "digest"))):
        raise Failure("adapter_receipt_conflict", "The node receipt belongs to a different operation.")
    original = {item["id"]: item for item in saved["resources"]}
    intents = {item["id"]: item for item in saved["intent"]["targets"]}
    for resource, intent in zip(binding["resources"], binding["intent"]["targets"], strict=True):
        if original.get(resource["id"]) != resource or intents.get(intent["id"]) != intent or intent["id"] != resource["id"]:
            raise Failure("adapter_receipt_conflict", "The node receipt resource or intent changed.")


def prepare(base, checksum, binding, phase):
    path = location(base, binding["id"], binding["intent"])
    exists = path.exists() or path.is_symlink()
    if exists:
        saved = loads(read(path))
        matching(saved, checksum, binding)
        if saved.get("cleanup"):
            raise Failure("adapter_receipt_cleanup", "Node receipt removal has started. Retry removal.")
        rows = {item["id"]: item for item in saved["results"]}
        result = {"results": [copy.deepcopy(rows[resource["id"]]) for resource in binding["resources"]]}
        return path, saved, result
    if phase != "apply":
        raise Failure("adapter_receipt_missing", "The node receipt is missing. The outcome remains unknown.")
    if (len(list(path.parent.glob("*.json"))) >= 1024 or
            sum(item.stat().st_size for item in path.parent.glob("*.json")) + 1024 * 1024 > 16 * 1024 * 1024):
        raise Failure("adapter_receipt_capacity", "The node provider receipt storage is full.")
    saved = {"digest": checksum, "profile_id": binding["id"], "intent": binding["intent"],
             "resources": binding["resources"], "results": [unknown(item) for item in binding["resources"]]}
    saved["identity"] = hashlib.sha256(dumps({key: saved[key] for key in ("digest", "profile_id", "intent", "resources")})).hexdigest()
    write(path, saved)
    return path, saved, None


def completed(path, saved, result):
    rows = {item["id"]: item for item in result["results"]}
    saved["results"] = [copy.deepcopy(rows.get(item["id"], item)) for item in saved["results"]]
    write(path, saved)


def forget(base, parameters):
    fields(parameters, {"profile_id", "digest", "intent", "outcomes"})
    checksum = digest(parameters["digest"])
    path = location(base, parameters["profile_id"], parameters["intent"])
    if not path.exists() and not path.is_symlink():
        return {"removed": True}
    saved = loads(read(path))
    if saved["digest"] != checksum or saved["intent"] != parameters["intent"] or saved["profile_id"] != parameters["profile_id"]:
        raise Failure("adapter_receipt_conflict", "The cleanup request does not match the node receipt.")
    outcomes = parameters["outcomes"]
    if not isinstance(outcomes, list) or len(outcomes) != len(saved["results"]):
        raise Failure("adapter_receipt_conflict", "The cleanup request must complete the original resource batch.")
    for item, outcome in zip(saved["results"], outcomes, strict=True):
        fields(outcome, {"id", "state"})
        state = item["receipt"]["state"]
        terminal = {"observed", "failed", "refused", "resolved"}
        valid = outcome["state"] in terminal and (state == outcome["state"]
            or state == "accepted" and outcome["state"] in {"observed", "failed", "resolved"}
            or state == "unknown" and outcome["state"] == "resolved")
        if outcome["id"] != item["id"] or not valid:
            raise Failure("adapter_receipt_conflict", "The cleanup terminal proof does not match the node receipt.")
    saved["cleanup"] = outcomes
    write(path, saved)
    path.unlink()
    sync(path.parent)
    return {"removed": True}
