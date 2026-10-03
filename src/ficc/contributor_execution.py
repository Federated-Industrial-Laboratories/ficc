# SPDX-License-Identifier: Apache-2.0
"""Relay typed controller commands to the root-owned local executor socket."""

import asyncio
import time

import httpx

from .contributor_client import post
from .execution.client import Client
from .execution.protocol import MAX_MESSAGE, MESSAGE
from .execution.wire import Error, FailureReply


class Execution:
    def __init__(self, state, socket_path):
        self.state = state
        self.client = Client(socket_path)
        self.current: dict | None = None
        self.available = False

    def connection(self, value, session_id, deadline):
        self.current = {"value": value, "session_id": session_id, "deadline": deadline,
                        "certificate": value["current"].copy()}

    def disconnected(self):
        self.current = None
        self.available = False

    def valid(self, current):
        return (self.current is not None and self.current["session_id"] == current["session_id"]
                and self.current["certificate"] == current["certificate"]
                and min(current["deadline"], self.current["deadline"]) > time.monotonic())

    async def run(self):
        response, session_id = None, None
        while True:
            current = self.current
            if current is None or not self.valid(current):
                response, session_id, self.available = None, None, False
                await asyncio.sleep(0.2)
                continue
            if current["session_id"] != session_id:
                response, session_id = None, current["session_id"]
            value = current["value"]
            try:
                result = await post(self.state, value, "/api/v1/node-channel/execution",
                    {"version": 1, "session_id": session_id, "response": response}, current["certificate"], maximum=MAX_MESSAGE)
                response = None
                if (not isinstance(result, dict) or set(result) != {"version", "deployment_id", "node_id", "session_id", "command"}
                        or type(result["version"]) is not int or result["version"] != 1
                        or result["deployment_id"] != value["deployment_id"] or result["node_id"] != value["node_id"]
                        or result["session_id"] != session_id):
                    raise ValueError("The controller execution response has an invalid identity.")
                if not self.valid(current):
                    continue
                if result["command"] is None:
                    await asyncio.sleep(0.1)
                    continue
                command = MESSAGE.validate_python(result["command"])
                if command.action == "set_offer":
                    raise ValueError("A controller cannot change the local contribution offer.")
                try:
                    response = await self.client.request(command)
                    if (response["deployment_id"], response["node_id"]) != (value["deployment_id"], value["node_id"]):
                        raise ValueError("The local executor belongs to another node or deployment.")
                    self.available = response["ok"]
                except (OSError, ValueError, TimeoutError):
                    self.available = False
                    response = FailureReply(version=1, id=command.id, ok=False, deployment_id=value["deployment_id"],
                        node_id=value["node_id"], error=Error(code="executor_unavailable",
                        message="The local executor did not return a verified response.")).model_dump()
                if not self.valid(current):
                    response = None
            except (OSError, ValueError, httpx.HTTPError, TimeoutError):
                response, self.available = None, False
                await asyncio.sleep(1)
