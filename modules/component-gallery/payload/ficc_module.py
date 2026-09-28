# SPDX-License-Identifier: Apache-2.0
"""Serve one bounded host request through standard input and standard output."""

import json
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
        hello, request = _frame(stream), _frame(stream)
        if (hello != {"version": 2, "type": "hello", "host_api": 1}
                or type(hello["version"]) is not int or type(hello["host_api"]) is not int
                or not isinstance(request, dict)
                or set(request) != {"version", "type", "id", "action", "targets", "parameters"}
                or type(request["version"]) is not int or request["version"] != 2
                or request["type"] != "invoke" or not isinstance(request["id"], str)
                or len(request["id"]) != 32 or not isinstance(request["action"], str)
                or not isinstance(request["parameters"], dict)):
            raise ValueError("Invalid handshake or request")
        targets = request["targets"]
        if (not isinstance(targets, list) or not 1 <= len(targets) <= 64
                or any(not isinstance(t, str) or not 1 <= len(t) <= 128
                       or any(c in t for c in "/\\:\x00") for t in targets)
                or len(set(targets)) != len(targets)):
            raise ValueError("Invalid targets")
        _write(output, {"version": 2, "type": "hello", "protocol": 2})
        output.flush()
        calls = 0

        def broker(primitive, selected, parameters=None):
            nonlocal calls
            calls += 1
            if (calls > 16 or not selected or len(set(selected)) != len(selected)
                    or set(selected) - set(targets)):
                raise ValueError("Invalid broker targets or call count")
            identity = secrets.token_hex(16)
            _write(output, {"version": 2, "type": "broker", "id": identity,
                           "invocation_id": request["id"], "primitive": primitive,
                           "targets": list(selected), "parameters": parameters or {}})
            output.flush()
            response = _frame(stream)
            if response == {"version": 2, "type": "cancel", "id": request["id"]}:
                raise ValueError("The operation was cancelled")
            if (not isinstance(response, dict)
                    or set(response) != {"version", "type", "id", "invocation_id", "results"}
                    or type(response["version"]) is not int or response["version"] != 2
                    or response["type"] != "broker-result" or response["id"] != identity
                    or response["invocation_id"] != request["id"]
                    or not isinstance(response["results"], list)
                    or [row.get("target") for row in response["results"]] != list(selected)):
                raise ValueError("Invalid broker result")
            return response["results"]

        _write(output, {"version": 2, "type": "result", "id": request["id"],
                        "results": handler(request, broker)})
        output.flush()
        return 0
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OSError):
        print("Invalid module request or result.", file=sys.stderr)
        return 1
