# SPDX-License-Identifier: Apache-2.0
"""Serve one isolated provider request through the version-one adapter protocol."""

import json
import re
import secrets
import struct
import sys

from ficc_module import MAX_FRAME, _bounded, _read, _unique

HEX = re.compile(r"[0-9a-f]{32}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
PHASES = {"probe", "inventory", "status", "prepare", "apply", "observe", "console"}


def exact(value, required, optional=frozenset()):
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("Invalid adapter fields")


def identity(value, pattern=HEX):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError("Invalid adapter identity")


def request(value):
    exact(value, {"version", "type", "id", "digest", "phase", "action", "bindings"})
    identity(value["id"])
    identity(value["digest"], HASH)
    phase = value["phase"]
    if (type(value["version"]) is not int or value["version"] != 1 or value["type"] != "adapter-invoke"
            or not isinstance(phase, str) or phase not in PHASES
            or value["action"] not in ({"start", "shutdown"} if phase in {"prepare", "apply", "observe"} else {phase})):
        raise ValueError("Invalid adapter request")
    bindings = value["bindings"]
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= 64:
        raise ValueError("Invalid adapter bindings")
    ids, count = [], 0
    for binding in bindings:
        exact(binding, {"id", "endpoint_id", "endpoint_revision", "machine_identity", "consistency",
                        "resources", "parameters"}, {"intent", "receipt", "transport_binding_id"})
        identity(binding["id"])
        identity(binding["endpoint_id"])
        if "transport_binding_id" in binding:
            identity(binding["transport_binding_id"])
        identity(binding["machine_identity"], HASH)
        ids.append(binding["id"])
        if (type(binding["endpoint_revision"]) is not int or binding["endpoint_revision"] < 1
                or binding["consistency"] not in {"provider-lock", "checked-before-dispatch"}
                or not isinstance(binding["resources"], list) or len(binding["resources"]) > 64):
            raise ValueError("Invalid adapter binding")
        resources = []
        for resource in binding["resources"]:
            exact(resource, {"id", "key", "birth", "revision", "state"})
            identity(resource["id"])
            identity(resource["birth"], HASH)
            identity(resource["revision"], HASH)
            if (not isinstance(resource["key"], str) or not 1 <= len(resource["key"]) <= 128
                    or any(ord(char) < 32 for char in resource["key"])
                    or resource["state"] not in {"unknown", "running", "blocked", "paused", "shutting-down", "off", "crashed", "suspended"}):
                raise ValueError("Invalid adapter resource")
            resources.append(resource["id"])
        if len(set(resources)) != len(resources):
            raise ValueError("Repeated adapter resource")
        count += len(resources)
        if phase not in {"probe", "inventory"} and not resources:
            raise ValueError("Missing adapter resources")
        if ("intent" in binding) != (phase in {"apply", "observe"}) or ("receipt" in binding) != (phase == "observe"):
            raise ValueError("Invalid adapter phase data")
        for name in ("parameters", "intent", "receipt"):
            if name in binding and (not isinstance(binding[name], dict)
                    or len(json.dumps(binding[name], ensure_ascii=True).encode()) > 65536):
                raise ValueError("Invalid private adapter data")
    if len(set(ids)) != len(ids) or (count != 0 if phase in {"probe", "inventory"} else not 1 <= count <= 64):
        raise ValueError("Invalid adapter batch")
    return value


def serve(handler):
    """Call handler(request, transport) once with the complete frozen host batch."""
    try:
        stream, output, totals = sys.stdin.buffer, sys.stdout.buffer, [0, 0]
        def receive():
            size = struct.unpack(">I", _read(stream, 4))[0]
            totals[0] += size + 4
            if not 0 < size <= MAX_FRAME or totals[0] > 2 * (MAX_FRAME + 4):
                raise ValueError("Invalid adapter input size")
            value = json.loads(_read(stream, size).decode("utf-8"), object_pairs_hook=_unique)
            _bounded(value)
            return value
        def send(value):
            _bounded(value)
            data = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
            totals[1] += len(data) + 4
            if not 0 < len(data) <= MAX_FRAME or totals[1] > 2 * (MAX_FRAME + 4):
                raise ValueError("Invalid adapter output size")
            output.write(struct.pack(">I", len(data)) + data)
            output.flush()
        hello, value = receive(), request(receive())
        if (hello != {"version": 1, "type": "adapter-hello", "host_api": 1}
                or type(hello["version"]) is not int or type(hello["host_api"]) is not int):
            raise ValueError("Invalid adapter handshake")
        invocation_id, profile_ids = value["id"], tuple(item["id"] for item in value["bindings"])
        send({"version": 1, "type": "adapter-hello", "protocol": 1})
        calls, failed, seen = 0, False, {invocation_id}
        def call(profile_id, commands):
            nonlocal calls
            calls += 1
            if calls > 16 or profile_id not in profile_ids or not isinstance(commands, list) or not 1 <= len(commands) <= 64:
                raise ValueError("Invalid adapter transport call")
            for command in commands:
                exact(command, {"command", "parameters"})
                if (not isinstance(command["command"], str) or not 1 <= len(command["command"]) <= 96
                        or any(ord(char) < 32 for char in command["command"]) or not isinstance(command["parameters"], dict)):
                    raise ValueError("Invalid adapter transport command")
            _bounded(commands)
            if len(json.dumps(commands, ensure_ascii=True).encode()) > 65536:
                raise ValueError("Invalid adapter transport size")
            count = len(commands)
            call_id = secrets.token_hex(16)
            while call_id in seen:
                call_id = secrets.token_hex(16)
            seen.add(call_id)
            send({"version": 1, "type": "adapter-transport", "id": call_id,
                  "invocation_id": invocation_id, "profile_id": profile_id, "commands": commands})
            result = receive()
            if result == {"version": 1, "type": "adapter-cancel", "id": invocation_id}:
                raise ValueError("The provider request was cancelled")
            exact(result, {"version", "type", "id", "invocation_id", "profile_id", "results"})
            if (type(result["version"]) is not int or result["version"] != 1 or result["type"] != "adapter-transport-result"
                    or result["id"] != call_id or result["invocation_id"] != invocation_id
                    or result["profile_id"] != profile_id or not isinstance(result["results"], list)
                    or len(result["results"]) != count):
                raise ValueError("Invalid adapter transport result")
            return result["results"]
        def transport(profile_id, commands):
            nonlocal failed
            if failed:
                raise ValueError("The adapter transport context has failed")
            try:
                return call(profile_id, commands)
            except Exception:
                failed = True
                raise
        results = handler(value, transport)
        if failed or not isinstance(results, list) or len(results) != len(profile_ids):
            raise ValueError("Invalid adapter final result")
        for result, profile_id in zip(results, profile_ids, strict=True):
            exact(result, {"profile_id"}, {"data", "error"})
            if result["profile_id"] != profile_id or ("data" in result) == ("error" in result):
                raise ValueError("Invalid adapter result identity")
            if "data" in result and not isinstance(result["data"], dict):
                raise ValueError("Invalid adapter result data")
            if "error" in result:
                exact(result["error"], {"code", "message"})
                if (not isinstance(result["error"]["code"], str)
                        or re.fullmatch(r"[a-z][a-z0-9_.-]{0,95}", result["error"]["code"]) is None
                        or not isinstance(result["error"]["message"], str) or not 1 <= len(result["error"]["message"]) <= 1024):
                    raise ValueError("Invalid adapter result error")
        send({"version": 1, "type": "adapter-result", "id": invocation_id, "results": results})
        return 0
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OSError):
        print("Invalid provider request or result.", file=sys.stderr)
        return 1
