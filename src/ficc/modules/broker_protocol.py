# SPDX-License-Identifier: Apache-2.0
"""Bind a finite protocol-two conversation to host-owned invocation authority."""

import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ..errors import Failure
from . import protocol
from .registry import targets
from .validation import dumps, fields, identifier, invalid, loads

MAX_CALLS = 16
MAX_PARAMETERS = 65536
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True)
class BrokerCall:
    invocation_id: str
    request_id: str
    primitive: str
    target_ids: tuple[str, ...]
    parameters: dict
    package_digest: str
    action_id: str
    action_capabilities: tuple[str, ...]
    check: Callable[[], None]


Broker = Callable[[BrokerCall], Awaitable[list[dict]]]


class Conversation:
    def __init__(self, digest: str, action: str, target_ids: list[str], parameters: dict,
                 capabilities: list[str], check: Callable[[], None], broker: Broker | None):
        self.id = secrets.token_hex(16)
        self.digest, self.action = digest, action
        self.targets = tuple(target_ids)
        self.capabilities = tuple(capabilities)
        self.check, self.broker = check, broker
        self.seen: set[str] = set()
        self.payload = protocol.frame({"version": 2, "type": "hello", "host_api": 1})
        self.payload += protocol.frame({"version": 2, "type": "invoke", "id": self.id,
            "action": action, "targets": list(self.targets), "parameters": parameters})
        self.cancel = protocol.frame({"version": 2, "type": "cancel", "id": self.id})

    def call(self, value: dict) -> BrokerCall:
        fields(value, {"version", "type", "id", "invocation_id", "primitive", "targets", "parameters"})
        if (type(value["version"]) is not int or value["version"] != 2 or value["type"] != "broker"
                or value["invocation_id"] != self.id or not isinstance(value["id"], str)
                or not REQUEST_ID.fullmatch(value["id"]) or value["id"] == self.id
                or value["id"] in self.seen or len(self.seen) >= MAX_CALLS):
            raise invalid("The module broker identity, version or call count is invalid.")
        identifier(value["primitive"])
        requested = tuple(targets(value["targets"]))
        if set(requested) - set(self.targets):
            raise invalid("The broker targets exceed the frozen invocation scope.")
        if not isinstance(value["parameters"], dict):
            raise invalid("Broker parameters must be an object.")
        parameters = loads(dumps(value["parameters"]), maximum=MAX_PARAMETERS)
        self.seen.add(value["id"])
        return BrokerCall(self.id, value["id"], value["primitive"], requested, parameters,
                          self.digest, self.action, self.capabilities, self.check)

    async def exchange(self, channel) -> bytes:
        hello = await channel.receive()
        fields(hello, {"version", "type", "protocol"})
        if (type(hello["version"]) is not int or hello["version"] != 2
                or type(hello["protocol"]) is not int or hello["protocol"] != 2
                or hello["type"] != "hello"):
            raise invalid("The module protocol handshake is unsupported.")
        while True:
            value = await channel.receive()
            self.check()
            if value.get("type") == "result":
                protocol.result_frame(value, self.id, list(self.targets), version=2)
                await channel.complete()
                self.check()
                return protocol.frame(hello) + protocol.frame(value)
            call = self.call(value)
            if self.broker is None or not self.capabilities:
                raise Failure("module_capability_unavailable", "No broker authority is available.", 409)
            self.check()
            results = await channel.dispatch(self.broker(call))
            self.check()
            # Copy host data before validation so a callback cannot mutate a pending frame.
            copied = loads(dumps({"results": results}))["results"]
            reply = {"version": 2, "type": "broker-result", "id": call.request_id,
                     "invocation_id": self.id,
                     "results": protocol.batch_results(copied, list(call.target_ids))}
            await channel.send(protocol.frame(reply))
