# SPDX-License-Identifier: Apache-2.0
"""Validate bounded admin identities and the fixed provider request protocol."""

import hashlib
import json
import re

MAX_MESSAGE = 1024 * 1024
PROVIDERS = {"systemd"}
KINDS = {"system", "service"}
ACTIONS = {"start", "stop", "restart", "reboot", "poweroff"}
POWER = {"reboot", "poweroff"}
POWER_ACCESS = {"yes", "no", "challenge", "na", "unavailable"}
EXPECTED = ("resource", "state", "revision", "definition", "boot_id", "invocation")
TERMINAL = {"refused", "observed", "resolved"}
HEX = re.compile(r"[a-f0-9]{32}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
UNIT = re.compile(r"[a-zA-Z0-9_:.-][a-zA-Z0-9_:@.\\-]{0,247}\.service\Z")
RESOURCE = re.compile(r"adm-([a-f0-9]{32})-(system|service)-([a-f0-9]{64})\Z")


class ProviderError(ValueError):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


def error(code, message):
    return {"code": code, "message": message}


def fields(value, required, optional=frozenset()):
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("Invalid admin protocol fields.")
    return value


def identity(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("Invalid admin identity.")
    return value


def fingerprint(value):
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ValueError("Invalid admin content digest.")
    return value


def text(value, maximum=256, empty=False):
    if not isinstance(value, str) or (not value and not empty) or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid admin text.")
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Invalid admin integer.")
    return value


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    if len(raw) > MAX_MESSAGE:
        raise ValueError("The admin message exceeds its byte limit.")
    return raw


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def decode(raw):
    def unique(pairs):
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError("Duplicate admin JSON key.")
        return value
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_MESSAGE:
        raise ValueError("The admin message exceeds its byte limit.")
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number.")))
    count = 0
    def walk(item, depth=0):
        nonlocal count
        count += 1
        if depth > 32 or count > 65536:
            raise ValueError("The admin data exceeds its depth or item limit.")
        if isinstance(item, dict):
            for child in item.values():
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
    walk(value)
    return value


def unit(value):
    text(value, 256)
    if not UNIT.fullmatch(value) or value.endswith('@.service'):
        raise ValueError("Select an installed service instance.")
    return value


def pointer(value):
    fields(value, {"kind", "id", "name"})
    if value["kind"] not in KINDS:
        raise ValueError("Invalid administration resource kind.")
    fingerprint(value["id"])
    if value["kind"] == "service":
        unit(value["name"])
    elif value["name"] != "system":
        raise ValueError("Invalid system resource name.")
    return value


def resource(profile, value):
    return f"adm-{identity(profile)}-{pointer(value)['kind']}-{value['id']}"


def resource_parts(value):
    match = RESOURCE.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise ValueError("Invalid admin selection identity.")
    return match.groups()


def batch(value, validator=pointer):
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ValueError("Select one to 64 admin resources.")
    for item in value:
        validator(item)
    pointers = [item["resource"] if "resource" in item else item for item in value]
    ids = [(item["kind"], item["id"]) for item in pointers]
    if len(ids) != len(set(ids)):
        raise ValueError("Administration targets must be distinct.")
    return value


def expected(value):
    fields(value, set(EXPECTED))
    pointer(value["resource"])
    text(value["state"], 64)
    fingerprint(value["revision"])
    fingerprint(value["definition"])
    identity(value["boot_id"])
    if value["invocation"] != "":
        identity(value["invocation"])
    return value


def capability(action):
    if action not in ACTIONS:
        raise ValueError("Invalid administration action.")
    return "admin:power" if action in POWER else "admin:services"


def request(value):
    fields(value, {"version", "action", "profile", "provider", "manager", "binding", "parameters"})
    if type(value["version"]) is not int or value["version"] != 1 or value["provider"] not in PROVIDERS:
        raise ValueError("Invalid admin provider request.")
    identity(value["profile"])
    config(value)
    if value["binding"] is not None:
        fingerprint(value["binding"])
    action, params = value["action"], value["parameters"]
    if action == "probe":
        fields(params, set())
    elif value["binding"] is None:
        raise ValueError("The admin profile must be registered first.")
    elif action == "list":
        fields(params, {"kind", "offset", "limit"})
        if params["kind"] not in KINDS | {"all"}:
            raise ValueError("Invalid admin inventory kind.")
        integer(params["offset"], 0, 4096)
        integer(params["limit"], 1, 256)
    elif action in {"status", "logs"}:
        fields(params, {"resources"} | ({"tail", "byte_limit"} if action == "logs" else set()))
        batch(params["resources"])
        if action == "logs":
            integer(params["tail"], 1, 200)
            integer(params["byte_limit"], 1, min(65536, 262144 // len(params["resources"])))
    elif action in {"apply", "receipt", "forget"}:
        fields(params, {"controller", "operation", "intent"} | ({"outcomes"} if action == "forget" else set()))
        identity(params["controller"])
        identity(params["operation"])
        intent = fields(params["intent"], {"action", "expected"})
        if intent["action"] not in ACTIONS:
            raise ValueError("Invalid admin state action.")
        batch(intent["expected"], expected)
        if action == "forget":
            outcomes = params["outcomes"]
            if not isinstance(outcomes, list) or len(outcomes) != len(intent["expected"]):
                raise ValueError("Invalid terminal admin outcomes.")
            for outcome, frozen in zip(outcomes, intent["expected"], strict=True):
                fields(outcome, {"resource", "state"})
                if outcome["resource"] != frozen["resource"] or outcome["state"] not in TERMINAL:
                    raise ValueError("Only exact terminal admin outcomes can be removed.")
    else:
        raise ValueError("Invalid admin action.")
    return value


def config(value):
    if value["provider"] != "systemd" or value["manager"] not in {"user", "system"}:
        raise ValueError("Select the user or system service manager.")
