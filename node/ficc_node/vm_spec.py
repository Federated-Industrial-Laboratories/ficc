# SPDX-License-Identifier: Apache-2.0
"""Validate the bounded, fixed-connection libvirt helper protocol."""

import hashlib
import json
import re

HEX = re.compile(r"[0-9a-f]{32}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
RESOURCE = re.compile(r"libvirt-([0-9a-f]{32})-([0-9a-f]{32})\Z")
CONNECTIONS = {"system": "qemu:///system", "session": "qemu:///session"}
STATES = {0: "unknown", 1: "running", 2: "blocked", 3: "paused", 4: "shutting-down",
          5: "off", 6: "crashed", 7: "suspended"}
MAX_MESSAGE = 1024 * 1024
TERMINAL = frozenset({"refused", "observed", "resolved"})


def fields(value, required, optional=frozenset()):
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("Invalid VM protocol fields.")
    return value


def identity(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("Invalid VM protocol identity.")
    return value


def fingerprint(value):
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ValueError("Invalid VM definition digest.")
    return value


def text(value, maximum=256):
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid VM text.")
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Invalid VM integer.")
    return value


def uuids(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ValueError("A VM batch must contain one to 64 identities.")
    for item in value:
        identity(item)
    if len(set(value)) != len(value):
        raise ValueError("Duplicate VM identities.")
    return value


def resource(value):
    match = RESOURCE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("Invalid VM resource identity.")
    return match.groups()


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MAX_MESSAGE:
        raise ValueError("The VM response exceeds the byte limit.")
    return raw


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate VM JSON field.")
            value[key] = item
        return value
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_MESSAGE:
        raise ValueError("The VM message exceeds the byte limit.")
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number.")))


def request(value):
    fields(value, {"version", "action", "connection", "profile", "parameters"})
    if type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("Unsupported VM protocol version.")
    if value["connection"] not in CONNECTIONS:
        raise ValueError("Unsupported VM connection.")
    identity(value["profile"])
    action, params = value["action"], value["parameters"]
    if action == "list":
        fields(params, {"offset", "limit"})
        integer(params["offset"], 0, 4096)
        integer(params["limit"], 1, 64)
    elif action in {"status", "console"}:
        fields(params, {"uuids"})
        uuids(params["uuids"])
        if action == "console" and len(params["uuids"]) != 1:
            raise ValueError("A console requires one VM.")
    elif action in {"apply", "receipt", "forget"}:
        fields(params, {"controller", "operation", "intent"} | ({"outcomes"} if action == "forget" else set()))
        identity(params["controller"])
        identity(params["operation"])
        fields(params["intent"], {"action", "expected"})
        intent = params["intent"]
        if intent["action"] not in {"start", "shutdown"}:
            raise ValueError("Unsupported VM lifecycle action.")
        if not isinstance(intent["expected"], list):
            raise ValueError("Invalid VM lifecycle batch.")
        uuids([item.get("uuid") if isinstance(item, dict) else None for item in intent["expected"]])
        for item in intent["expected"]:
            fields(item, {"uuid", "definition", "state"})
            fingerprint(item["definition"])
            if item["state"] not in STATES.values():
                raise ValueError("Invalid VM state.")
        if action == "forget":
            outcomes = params["outcomes"]
            if not isinstance(outcomes, list) or len(outcomes) != len(intent["expected"]):
                raise ValueError("Invalid VM receipt cleanup batch.")
            for expected, outcome in zip(intent["expected"], outcomes, strict=True):
                fields(outcome, {"uuid", "state"})
                if outcome["uuid"] != expected["uuid"] or outcome["state"] not in TERMINAL:
                    raise ValueError("Invalid VM receipt cleanup identity or state.")
    else:
        raise ValueError("Unsupported VM helper action.")
    return value
