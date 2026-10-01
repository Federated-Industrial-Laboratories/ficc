# SPDX-License-Identifier: Apache-2.0
"""Bind isolated provider exchanges to immutable host profiles and complete batches."""

import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from .adapter_manifest import CONSISTENCY
from .protocol import frame
from .validation import digest, dumps, fields, identifier, invalid, loads, text

HEX = re.compile(r"[0-9a-f]{32}\Z")
PHASES = {"probe", "inventory", "status", "prepare", "apply", "observe", "console"}
STATES = {"unknown", "running", "blocked", "paused", "shutting-down", "off", "crashed", "suspended"}
MAX_CALLS = 16
MAX_PRIVATE = 65536


def identity(value) -> str:
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise invalid("The adapter identity is invalid.")
    return value


def integer(value, low=1, high=9007199254740991) -> int:
    if type(value) is not int or not low <= value <= high:
        raise invalid("The adapter integer is invalid.")
    return value


def plain(value, maximum=128) -> str:
    result = text(value, maximum)
    if not result or any(ord(char) < 32 for char in result):
        raise invalid("The adapter text is empty or contains control characters.")
    return result


def private(value) -> dict:
    if not isinstance(value, dict):
        raise invalid("Private adapter data must be an object.")
    return loads(dumps(value), MAX_PRIVATE)


def resource(value) -> dict:
    fields(value, {"id", "key", "birth", "revision", "state"})
    identity(value["id"])
    plain(value["key"])
    digest(value["birth"])
    digest(value["revision"])
    if not isinstance(value["state"], str) or value["state"] not in STATES:
        raise invalid("The adapter VM state is invalid.")
    return value


def binding(value) -> dict:
    fields(value, {"id", "endpoint_id", "endpoint_revision", "machine_identity", "consistency",
                   "resources", "parameters"}, {"intent", "receipt", "transport_binding_id"})
    identity(value["id"])
    identity(value["endpoint_id"])
    if "transport_binding_id" in value:
        identity(value["transport_binding_id"])
    integer(value["endpoint_revision"])
    digest(value["machine_identity"])
    if not isinstance(value["consistency"], str) or value["consistency"] not in CONSISTENCY:
        raise invalid("The adapter consistency class is invalid.")
    resources = value["resources"]
    if not isinstance(resources, list) or len(resources) > 64:
        raise invalid("The adapter resource batch exceeds its limit.")
    ids = [resource(item)["id"] for item in resources]
    if len(ids) != len(set(ids)):
        raise invalid("The adapter resource batch repeats an identity.")
    for name in ("parameters", "intent", "receipt"):
        if name in value:
            private(value[name])
    return value


def request(value) -> dict:
    fields(value, {"version", "type", "id", "digest", "phase", "action", "bindings"})
    if type(value["version"]) is not int or value["version"] != 1 or value["type"] != "adapter-invoke":
        raise invalid("The adapter request version is unsupported.")
    identity(value["id"])
    digest(value["digest"])
    phase, action = value["phase"], value["action"]
    if not isinstance(phase, str) or phase not in PHASES:
        raise invalid("The adapter phase is unsupported.")
    if (not isinstance(action, str)
            or action not in ({"start", "shutdown"} if phase in {"prepare", "apply", "observe"} else {phase})):
        raise invalid("The adapter action does not match its phase.")
    bindings = value["bindings"]
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= 64:
        raise invalid("An adapter request requires one to 64 profiles.")
    ids = [binding(item)["id"] for item in bindings]
    if len(set(ids)) != len(ids):
        raise invalid("The adapter request repeats a profile.")
    count = sum(len(item["resources"]) for item in bindings)
    if (phase in {"probe", "inventory"} and count) or (phase not in {"probe", "inventory"} and not 1 <= count <= 64):
        raise invalid("The adapter resource count does not match its phase.")
    for item in bindings:
        if phase not in {"probe", "inventory"} and not item["resources"]:
            raise invalid("Every selected adapter profile requires resources.")
        if ("intent" in item) != (phase in {"apply", "observe"}):
            raise invalid("The adapter intent does not match its phase.")
        if ("receipt" in item) != (phase == "observe"):
            raise invalid("The adapter receipt does not match its phase.")
    return value


def commands(value) -> list[dict]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise invalid("The adapter transport requires one to 64 commands.")
    for item in value:
        fields(item, {"command", "parameters"})
        plain(item["command"], 96)
        private(item["parameters"])
    loads(dumps(value), MAX_PRIVATE)
    return value


@dataclass(frozen=True)
class TransportCall:
    invocation_id: str
    request_id: str
    profile_id: str
    package_digest: str
    phase: str
    command_bytes: bytes
    check: Callable[[], None]

    @property
    def commands(self) -> list[dict]:
        return loads(self.command_bytes, MAX_PRIVATE)


Transport = Callable[[TransportCall], Awaitable[list[dict]]]


class Conversation:
    def __init__(self, package_digest: str, phase: str, action: str, bindings: list[dict],
                 check: Callable[[], None], transport: Transport | None = None):
        self.id = secrets.token_hex(16)
        value = request(loads(dumps({"version": 1, "type": "adapter-invoke", "id": self.id,
            "digest": package_digest, "phase": phase, "action": action, "bindings": bindings})))
        self.request_bytes = dumps(value)
        self.profile_ids = tuple(item["id"] for item in value["bindings"])
        self.digest, self.phase = value["digest"], value["phase"]
        self.check, self.transport = check, transport
        self.seen: set[str] = set()
        self.payload = frame({"version": 1, "type": "adapter-hello", "host_api": 1}) + frame(value)
        self.cancel = frame({"version": 1, "type": "adapter-cancel", "id": self.id})

    @classmethod
    def received(cls, value: dict, check, transport=None):
        """Retain the exact host invocation when an enrolled helper supervises it."""
        value = request(loads(dumps(value)))
        result = cls(value["digest"], value["phase"], value["action"], value["bindings"], check, transport)
        result.id = value["id"]
        result.request_bytes = dumps(value)
        result.payload = frame({"version": 1, "type": "adapter-hello", "host_api": 1}) + frame(value)
        result.cancel = frame({"version": 1, "type": "adapter-cancel", "id": result.id})
        return result

    @property
    def request(self) -> dict:
        return loads(self.request_bytes)

    def call(self, value: dict) -> TransportCall:
        fields(value, {"version", "type", "id", "invocation_id", "profile_id", "commands"})
        identity(value["id"])
        if (type(value["version"]) is not int or value["version"] != 1 or value["type"] != "adapter-transport"
                or value["invocation_id"] != self.id or value["id"] == self.id or value["id"] in self.seen
                or value["profile_id"] not in self.profile_ids or len(self.seen) >= MAX_CALLS):
            raise invalid("The adapter transport identity, profile or call count is invalid.")
        raw = dumps(commands(value["commands"]))
        self.seen.add(value["id"])
        return TransportCall(self.id, value["id"], value["profile_id"], self.digest, self.phase, raw, self.check)

    def result(self, value: dict) -> dict:
        fields(value, {"version", "type", "id", "results"})
        if (type(value["version"]) is not int or value["version"] != 1
                or value["type"] != "adapter-result" or value["id"] != self.id):
            raise invalid("The adapter response identity is invalid.")
        rows = value["results"]
        if not isinstance(rows, list) or len(rows) != len(self.profile_ids):
            raise invalid("The adapter response must complete every profile.")
        for row, profile_id in zip(rows, self.profile_ids, strict=True):
            fields(row, {"profile_id"}, {"data", "error"})
            if row["profile_id"] != profile_id or ("data" in row) == ("error" in row):
                raise invalid("The adapter response order or outcome is invalid.")
            if "error" in row:
                fields(row["error"], {"code", "message"})
                identifier(row["error"]["code"])
                plain(row["error"]["message"], 1024)
            elif not isinstance(row["data"], dict):
                raise invalid("Adapter result data must be an object.")
        return loads(dumps(value))

    async def exchange(self, channel) -> bytes:
        hello = await channel.receive()
        fields(hello, {"version", "type", "protocol"})
        if (type(hello["version"]) is not int or hello["version"] != 1
                or type(hello["protocol"]) is not int or hello["protocol"] != 1
                or hello["type"] != "adapter-hello"):
            raise invalid("The adapter handshake is unsupported.")
        while True:
            value = await channel.receive()
            self.check()
            if value.get("type") == "adapter-result":
                result = self.result(value)
                await channel.complete()
                self.check()
                return dumps(result)
            call = self.call(value)
            if self.transport is None:
                raise invalid("This adapter has no host transport authority.")
            self.check()
            results = loads(dumps(await channel.dispatch(self.transport(call))))
            self.check()
            if not isinstance(results, list) or len(results) != len(call.commands):
                raise invalid("The adapter transport did not return every command result.")
            await channel.send(frame({"version": 1, "type": "adapter-transport-result",
                "id": call.request_id, "invocation_id": self.id, "profile_id": call.profile_id,
                "results": results}))
