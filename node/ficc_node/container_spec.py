# SPDX-License-Identifier: Apache-2.0
"""Validate bounded container identities and the fixed provider request protocol."""

import hashlib
import json
import re

MAX_MESSAGE = 1024 * 1024
PROVIDERS = {"docker", "podman", "kubernetes"}
KINDS = {"container", "pod", "deployment", "statefulset"}
ACTIONS = {"start", "stop", "scale"}
TERMINAL = {"refused", "observed", "resolved"}
HEX = re.compile(r"[a-f0-9]{32}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
DNS = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")
RESOURCE = re.compile(r"ctr-([a-f0-9]{32})-(container|pod|deployment|statefulset)-([a-f0-9]{32}|[a-f0-9]{64})\Z")


class ProviderError(ValueError):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


def error(code, message):
    return {"code": code, "message": message}


def fields(value, required, optional=frozenset()):
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("Invalid container protocol fields.")
    return value


def identity(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("Invalid container identity.")
    return value


def fingerprint(value):
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ValueError("Invalid container content digest.")
    return value


def text(value, maximum=256, empty=False):
    if not isinstance(value, str) or (not value and not empty) or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid container text.")
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Invalid container integer.")
    return value


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    if len(raw) > MAX_MESSAGE:
        raise ValueError("The container message exceeds its byte limit.")
    return raw


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def decode(raw):
    def unique(pairs):
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError("Duplicate container JSON key.")
        return value
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_MESSAGE:
        raise ValueError("The container message exceeds its byte limit.")
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number.")))
    count = 0
    def walk(item, depth=0):
        nonlocal count
        count += 1
        if depth > 32 or count > 65536:
            raise ValueError("The container data exceeds its depth or item limit.")
        if isinstance(item, dict):
            for child in item.values():
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
    walk(value)
    return value


def name(value, maximum=253):
    text(value, maximum)
    if not DNS.fullmatch(value):
        raise ValueError("Invalid Kubernetes object name.")
    return value


def pointer(value):
    fields(value, {"kind", "id", "name", "namespace"})
    if value["kind"] not in KINDS:
        raise ValueError("Invalid container resource kind.")
    if value["kind"] == "container":
        fingerprint(value["id"])
        text(value["name"])
        if value["namespace"] != "":
            raise ValueError("Invalid container namespace.")
    else:
        identity(value["id"])
        name(value["name"])
        name(value["namespace"], 63)
    return value


def resource(profile, value):
    return f"ctr-{identity(profile)}-{pointer(value)['kind']}-{value['id']}"


def resource_parts(value):
    match = RESOURCE.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise ValueError("Invalid container selection identity.")
    return match.groups()


def batch(value, validator=pointer):
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ValueError("Select one to 64 container resources.")
    for item in value:
        validator(item)
    pointers = [item["resource"] if "resource" in item else item for item in value]
    ids = [(item["kind"], item["id"], item["namespace"]) for item in pointers]
    if len(ids) != len(set(ids)):
        raise ValueError("Container targets must be distinct.")
    return value


def expected(value):
    fields(value, {"resource", "state", "revision", "definition", "replicas"})
    pointer(value["resource"])
    text(value["state"], 64)
    text(value["revision"], 128)
    fingerprint(value["definition"])
    if value["replicas"] is not None:
        integer(value["replicas"], 0, 1000000)
    return value


def request(value):
    fields(value, {"version", "action", "profile", "provider", "connection", "context", "namespace", "binding", "parameters"})
    if type(value["version"]) is not int or value["version"] != 1 or value["provider"] not in PROVIDERS:
        raise ValueError("Invalid container provider request.")
    identity(value["profile"])
    config(value)
    if value["binding"] is not None:
        fingerprint(value["binding"])
    action, params = value["action"], value["parameters"]
    if action == "probe":
        fields(params, set())
    elif value["binding"] is None:
        raise ValueError("The container profile must be registered first.")
    elif action == "list":
        fields(params, {"kind", "offset", "limit"})
        if params["kind"] not in KINDS | {"all"}:
            raise ValueError("Invalid container inventory kind.")
        integer(params["offset"], 0, 4096)
        integer(params["limit"], 1, 256)
    elif action in {"status", "logs"}:
        fields(params, {"resources"} | ({"tail", "byte_limit", "container"} if action == "logs" else set()))
        batch(params["resources"])
        if action == "logs":
            integer(params["tail"], 1, 200)
            integer(params["byte_limit"], 1, min(65536, 262144 // len(params["resources"])))
            text(params["container"], 63, empty=True)
    elif action in {"apply", "receipt", "forget"}:
        fields(params, {"controller", "operation", "intent"} | ({"outcomes"} if action == "forget" else set()))
        identity(params["controller"])
        identity(params["operation"])
        intent = fields(params["intent"], {"action", "replicas", "expected"})
        if intent["action"] not in ACTIONS:
            raise ValueError("Invalid container state action.")
        if intent["action"] == "scale":
            integer(intent["replicas"], 0, 64)
        elif intent["replicas"] is not None:
            raise ValueError("Replica count is only valid for scale.")
        batch(intent["expected"], expected)
        if action == "forget":
            outcomes = params["outcomes"]
            if not isinstance(outcomes, list) or len(outcomes) != len(intent["expected"]):
                raise ValueError("Invalid terminal container outcomes.")
            for outcome, frozen in zip(outcomes, intent["expected"], strict=True):
                fields(outcome, {"resource", "state"})
                if outcome["resource"] != frozen["resource"] or outcome["state"] not in TERMINAL:
                    raise ValueError("Only exact terminal container outcomes can be removed.")
    else:
        raise ValueError("Invalid container action.")
    return value


def config(value):
    if value["provider"] == "kubernetes":
        if value["connection"] != "context":
            raise ValueError("Select a Kubernetes context connection.")
        text(value["context"], 128)
        name(value["namespace"], 63)
    else:
        if value["connection"] not in ({"rootless", "rootful"} if value["provider"] == "docker" else {"rootless"}):
            raise ValueError("Select a supported local container socket.")
        if value["context"] != "" or value["namespace"] != "":
            raise ValueError("Engine sockets cannot select a Kubernetes context.")
