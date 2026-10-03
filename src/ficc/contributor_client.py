# SPDX-License-Identifier: Apache-2.0
"""Connect an approved Linux node with renewable TLS identity and polling fallback."""

import asyncio
import json
import math
import secrets
import time

import httpx
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from .contributor_settings import IDENTITY
from .remote_settings import https_url
from .state_provider import read_private


async def post(state, value, path, body=None, material=None, *, maximum=32768):
    origin = value["node_origin"] if material else value["controller"]
    async with httpx.AsyncClient(verify=state.tls(value, material), timeout=30,
                                follow_redirects=False, trust_env=False) as client:
        async with client.stream("POST", origin + path, json=body or {}) as response:
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > maximum:
                    raise ValueError("The controller response exceeds the limit.")
            if response.status_code >= 400:
                raise ValueError("The controller refused the node request. Check approval and certificate status.")
            if response.status_code != 200 and response.status_code != 201:
                raise ValueError("The controller returned an unexpected status.")
            return json.loads(data)


async def join(state, invitation, server_ca=None):
    if (state.path / "node.json").exists():
        raise ValueError("This node directory already has an identity. Resume its existing enrollment.")
    value = json.loads(read_private(invitation, 32768))
    expected = {"format", "version", "controller", "node_origin", "deployment_id", "node_id", "node_ca_pem", "name", "mode", "expires_at", "secret"}
    if (not isinstance(value, dict) or set(value) != expected or value["format"] != "ficc-node-invitation"
            or type(value["version"]) is not int or value["version"] != 1
            or not all(isinstance(value[key], str) and IDENTITY.fullmatch(value[key]) for key in ("deployment_id", "node_id"))
            or type(value["expires_at"]) not in {int, float} or not math.isfinite(value["expires_at"])
            or value["expires_at"] <= time.time() or value["mode"] not in {"managed", "voluntary"}):
        raise ValueError("The invitation is invalid or expired.")
    https_url(value["controller"], origin=True)
    https_url(value["node_origin"], origin=True)
    secret = value.pop("secret")
    if server_ca:
        from .launcher_config import write_file
        write_file(state.path / "server-ca.pem", read_private(server_ca, 65536).decode("ascii"))
        value["server_ca_file"] = "server-ca.pem"
    value["pending"] = state.key(value)
    value["stage"] = "claiming"
    state.save(value)
    # An uncertain claim does not replay a single-use invitation automatically.
    result = await post(state, value, "/api/v1/node-enrollment/claim", {
        "secret": secret, "node_id": value["node_id"], "csr_pem": value["pending"]["csr_pem"]})
    if result["node_id"] != value["node_id"] or result["public_key"] != value["pending"]["public_key"]:
        raise ValueError("The controller enrollment response names another key or node.")
    value.update(receipt=result["receipt"], request_id=result["request_id"], stage="awaiting_approval")
    state.save(value)
    return {"node_id": value["node_id"], "public_key": value["pending"]["public_key"], "status": value["stage"]}


async def activate(state, value):
    result = await post(state, value, "/api/v1/node-channel/activate", material=value["pending"])
    if result.get("node_id") != value["node_id"] or result.get("activated") is not True:
        raise ValueError("The controller did not acknowledge this node certificate.")
    state.promote(value)


async def complete_enrollment(state, value):
    if value["stage"] == "claiming":
        raise ValueError("The original invitation outcome is unknown. Ask the administrator to replace this enrollment.")
    if "certificate_file" not in value["pending"]:
        result = await post(state, value, "/api/v1/node-enrollment/status", {
            "request_id": value["request_id"], "receipt": value["receipt"]})
        if result.get("status") != "issued":
            return False
        state.accept_certificate(value, value["pending"], result["certificate_chain"])
        state.save(value)
    await activate(state, value)
    return True


async def rotate(state, value):
    if "pending" not in value:
        value["pending"] = {**state.key(value), "request_id": secrets.token_hex(16)}
        state.save(value)
    if "certificate_file" not in value["pending"]:
        result = await post(state, value, "/api/v1/node-channel/rotate", {
            "request_id": value["pending"]["request_id"], "csr_pem": value["pending"]["csr_pem"]}, value["current"])
        state.accept_certificate(value, value["pending"], result["certificate_chain"])
        state.save(value)
    await activate(state, value)


def acknowledgement(value, message, result, started):
    if (not isinstance(result, dict) or result.get("version") != 1
            or result.get("node_id") != value["node_id"] or result.get("sequence") != message["sequence"]
            or not isinstance(result.get("session_id"), str) or not IDENTITY.fullmatch(result["session_id"])
            or message["session_id"] is not None and result["session_id"] != message["session_id"]
            or type(result.get("lease_seconds")) not in {int, float}
            or not math.isfinite(result["lease_seconds"]) or not 0 < result["lease_seconds"] <= 30
            or type(result.get("heartbeat_seconds")) is not int or not 1 <= result["heartbeat_seconds"] <= 10
            or type(result.get("execution_available")) is not bool):
        raise ValueError("The controller returned an invalid node lease.")
    deadline = min(started + result["lease_seconds"],
                   time.monotonic() + value["current"]["expires_at"] - time.time())
    if deadline <= time.monotonic():
        raise ValueError("The contributor lease expired before receipt.")
    return deadline


async def run(state, transport="auto", once=False, executor_socket=None):
    value = state.load()
    websocket = None
    message: dict = {"version": 1, "session_id": None, "sequence": 1}
    interval, deadline, attempts = 5, 0.0, 0
    selected = "polling" if transport == "polling" else "persistent"
    execution, execution_task = None, None
    if executor_socket is not None:
        from .contributor_execution import Execution
        execution = Execution(state, executor_socket)
        execution_task = asyncio.create_task(execution.run())
    try:
        while True:
            try:
                if value["stage"] != "active":
                    if not await complete_enrollment(state, value):
                        state.report(status="awaiting_approval", node_id=value["node_id"], execution_available=False)
                        if once:
                            return {"status": "awaiting_approval", "node_id": value["node_id"]}
                        await asyncio.sleep(5)
                        continue
                current = value["current"]
                if "pending" in value or current["expires_at"] - time.time() < min(300, (current["expires_at"] - current["not_before"]) / 3):
                    if websocket:
                        await websocket.close()
                        websocket = None
                    await rotate(state, value)
                    message.update(session_id=None, sequence=1)
                    deadline = 0
                from ficc_node.collect import collect
                message["sample"] = await asyncio.to_thread(collect)
                if deadline <= time.monotonic():
                    if websocket is not None:
                        await websocket.close()
                        websocket = None
                    message.update(session_id=None, sequence=1)
                started = time.monotonic()
                if selected == "persistent":
                    if websocket is None:
                        websocket = await connect(value["node_origin"].replace("https://", "wss://", 1) + "/api/v1/node-channel/stream",
                            ssl=state.tls(value, value["current"]), proxy=None, open_timeout=10,
                            close_timeout=2, max_size=16384, max_queue=4, compression=None)
                    await websocket.send(json.dumps(message, allow_nan=False))
                    async with asyncio.timeout(10):
                        result = json.loads(await websocket.recv())
                else:
                    result = await post(state, value, "/api/v1/node-channel/poll", message, value["current"])
                deadline = acknowledgement(value, message, result, started)
                message.update(session_id=result["session_id"], sequence=message["sequence"] + 1)
                if execution:
                    execution.connection(value, result["session_id"], deadline)
                interval, attempts = result["heartbeat_seconds"], 0
                state.report(status="connected", node_id=value["node_id"], transport=selected,
                             observed_at=time.time(), lease_seconds=max(0, deadline - time.monotonic()),
                             execution_available=bool(execution and execution.available and result["execution_available"]))
                if once:
                    return {"status": "connected", "node_id": value["node_id"], "transport": selected, "execution_available": False}
            except (ValueError, OSError, httpx.HTTPError, WebSocketException, TimeoutError) as exc:
                if execution:
                    execution.disconnected()
                if once and (transport != "auto" or selected == "polling"):
                    raise ValueError("The contributor could not connect. Check enrollment, certificates and gateway reachability.") from exc
                state.report(status="disconnected", node_id=value["node_id"], observed_at=time.time(),
                             lease_seconds=max(0, deadline - time.monotonic()), execution_available=False)
                if websocket:
                    await websocket.close()
                    websocket = None
                attempts += 1
                if transport == "auto":
                    selected = "polling" if selected == "persistent" else "persistent" if attempts % 6 == 0 else "polling"
                interval = min(30, 2 ** min(attempts, 5))
            await asyncio.sleep(interval)
    finally:
        if execution_task:
            execution_task.cancel()
            await asyncio.gather(execution_task, return_exceptions=True)
        if websocket:
            await websocket.close()
        state.report(status="stopped", node_id=value["node_id"], observed_at=time.time(), lease_seconds=0, execution_available=False)
