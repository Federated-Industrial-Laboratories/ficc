# SPDX-License-Identifier: Apache-2.0
"""Serve one bounded host request through standard input and standard output."""

import json
import math
import re
import secrets
import struct
import sys

MAX_FRAME = 1024 * 1024


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key")
        value[key] = item
    return value


def _read(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise ValueError("Incomplete frame")
        data.extend(chunk)
    return bytes(data)


def _frame(stream):
    size = struct.unpack(">I", _read(stream, 4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("Invalid frame size")
    return json.loads(_read(stream, size).decode("utf-8"), object_pairs_hook=_unique)


def _write(stream, value):
    data = json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")
    if not 0 < len(data) <= MAX_FRAME:
        raise ValueError("Invalid output size")
    stream.write(struct.pack(">I", len(data)) + data)


def serve(handler):
    """Call handler once with the complete batch. Return a process exit code."""
    try:
        stream = sys.stdin.buffer
        hello, request = _frame(stream), _frame(stream)
        if stream.read(1) or hello != {"version": 1, "type": "hello", "host_api": 1}:
            raise ValueError("Invalid handshake")
        if (type(hello["version"]) is not int or type(hello["host_api"]) is not int
                or not isinstance(request, dict)
                or set(request) != {"version", "type", "id", "action", "targets", "parameters"}
                or type(request["version"]) is not int or request["version"] != 1
                or request["type"] != "invoke" or not isinstance(request["id"], str)
                or not 1 <= len(request["id"]) <= 128
                or not isinstance(request["action"], str)
                or not isinstance(request["parameters"], dict)):
            raise ValueError("Invalid request")
        targets = request["targets"]
        if (not isinstance(targets, list) or not 1 <= len(targets) <= 64
                or any(not isinstance(t, str) or not 1 <= len(t) <= 128
                       or any(c in t for c in "/\\:\x00") for t in targets)
                or len(set(targets)) != len(targets)):
            raise ValueError("Invalid targets")
        result = {"version": 1, "type": "result", "id": request["id"],
                  "results": handler(request)}
        # Encode both frames before writing to avoid a partial success response.
        import io
        output = io.BytesIO()
        _write(output, {"version": 1, "type": "hello", "protocol": 1})
        _write(output, result)
        sys.stdout.buffer.write(output.getvalue())
        sys.stdout.buffer.flush()
        return 0
    except (ValueError, TypeError, KeyError, RecursionError, OSError):
        print("Invalid module request or result.", file=sys.stderr)
        return 1


def serve_broker(handler):
    """Call handler(request, broker) once with bounded protocol-two host access."""
    try:
        stream, output = sys.stdin.buffer, sys.stdout.buffer
        totals = [0, 0]

        def receive():
            size = struct.unpack(">I", _read(stream, 4))[0]
            totals[0] += size + 4
            if not 0 < size <= MAX_FRAME or totals[0] > 2 * (MAX_FRAME + 4):
                raise ValueError("Invalid input size")
            value = json.loads(_read(stream, size).decode("utf-8"), object_pairs_hook=_unique)
            _bounded(value)
            return value

        def send(value):
            _bounded(value)
            data = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
            totals[1] += len(data) + 4
            if not 0 < len(data) <= MAX_FRAME or totals[1] > 2 * (MAX_FRAME + 4):
                raise ValueError("Invalid output size")
            output.write(struct.pack(">I", len(data)) + data)
            output.flush()

        hello, request = receive(), receive()
        if (hello != {"version": 2, "type": "hello", "host_api": 1}
                or type(hello["version"]) is not int or type(hello["host_api"]) is not int
                or not isinstance(request, dict)
                or set(request) != {"version", "type", "id", "action", "targets", "parameters"}
                or type(request["version"]) is not int or request["version"] != 2
                or request["type"] != "invoke" or not isinstance(request["id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", request["id"])
                or not isinstance(request["action"], str)
                or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,95}", request["action"])
                or not isinstance(request["parameters"], dict)):
            raise ValueError("Invalid handshake or request")
        targets = request["targets"]
        if (not isinstance(targets, list) or not 1 <= len(targets) <= 64
                or any(not isinstance(t, str) or not 1 <= len(t) <= 128
                       or any(c in t for c in "/\\:\x00") for t in targets)
                or len(set(targets)) != len(targets)):
            raise ValueError("Invalid targets")
        send({"version": 2, "type": "hello", "protocol": 2})
        invocation_id, targets = request["id"], tuple(targets)
        calls, failed = 0, False

        def call(primitive, selected, parameters=None):
            nonlocal calls
            calls += 1
            if (calls > 16 or not isinstance(selected, (tuple, list)) or not selected
                    or len(set(selected)) != len(selected)
                    or set(selected) - set(targets)):
                raise ValueError("Invalid broker targets or call count")
            selected = tuple(selected)
            if not isinstance(primitive, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,95}", primitive):
                raise ValueError("Invalid primitive")
            parameters = {} if parameters is None else parameters
            _bounded(parameters)
            if not isinstance(parameters, dict) or len(json.dumps(parameters, ensure_ascii=True).encode()) > 65536:
                raise ValueError("Invalid broker parameters")
            identity = secrets.token_hex(16)
            send({"version": 2, "type": "broker", "id": identity,
                           "invocation_id": invocation_id, "primitive": primitive,
                           "targets": list(selected), "parameters": parameters})
            response = receive()
            if response == {"version": 2, "type": "cancel", "id": invocation_id}:
                raise ValueError("The operation was cancelled")
            if (not isinstance(response, dict)
                    or set(response) != {"version", "type", "id", "invocation_id", "results"}
                    or type(response["version"]) is not int or response["version"] != 2
                    or response["type"] != "broker-result" or response["id"] != identity
                    or response["invocation_id"] != invocation_id
                    or not isinstance(response["results"], list)):
                raise ValueError("Invalid broker result")
            _results(response["results"], selected)
            return response["results"]

        def broker(primitive, selected, parameters=None):
            nonlocal failed
            if failed:
                raise ValueError("The broker context has failed")
            try:
                return call(primitive, selected, parameters)
            except Exception:
                failed = True
                raise

        results = handler(request, broker)
        if failed:
            raise ValueError("The broker context has failed")
        _results(results, targets)
        send({"version": 2, "type": "result", "id": invocation_id, "results": results})
        return 0
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OSError):
        print("Invalid module request or result.", file=sys.stderr)
        return 1


def _bounded(value, depth=0):
    if depth > 12:
        raise ValueError("Invalid JSON depth")
    if isinstance(value, (dict, list)):
        if len(value) > 256:
            raise ValueError("Invalid JSON collection")
        for key, item in value.items() if isinstance(value, dict) else enumerate(value):
            if isinstance(value, dict) and (not isinstance(key, str) or len(key) > 240 or "\x00" in key):
                raise ValueError("Invalid JSON key")
            _bounded(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 65536 or "\x00" in value:
            raise ValueError("Invalid JSON text")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Invalid JSON number")
    elif type(value) is int and abs(value) > 9007199254740991:
        raise ValueError("Invalid JSON integer")
    elif value is not None and type(value) not in (int, bool):
        raise ValueError("Invalid JSON value")


def _results(results, targets):
    if not isinstance(results, list) or len(results) != len(targets):
        raise ValueError("Invalid result count")
    for item, target in zip(results, targets, strict=True):
        if (not isinstance(item, dict) or item.get("target") != target
                or set(item) not in ({"target", "data"}, {"target", "error"})):
            raise ValueError("Invalid result target or outcome")
        if "error" in item:
            error = item["error"]
            if (not isinstance(error, dict) or set(error) != {"code", "message"}
                    or not isinstance(error["code"], str)
                    or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,95}", error["code"])
                    or not isinstance(error["message"], str) or len(error["message"]) > 1024):
                raise ValueError("Invalid result error")
