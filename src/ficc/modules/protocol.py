# SPDX-License-Identifier: Apache-2.0
"""Encode one bounded batch request and validate its complete framed response."""

import secrets
import struct

from .validation import MAX_JSON, dumps, fields, identifier, invalid, loads, text

MAX_OUTPUT = 2 * (MAX_JSON + 4)
MAX_STDERR = 65536


def frame(value: dict) -> bytes:
    payload = dumps(value)
    return struct.pack(">I", len(payload)) + payload


def frames(data: bytes) -> list[dict]:
    if len(data) > MAX_OUTPUT:
        raise invalid("The module response exceeds the protocol limit.")
    result: list[dict] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4 or len(result) >= 2:
            raise invalid("The module returned an incomplete or extra frame.")
        size = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        if not 0 < size <= MAX_JSON or offset + size > len(data):
            raise invalid("The module frame size is invalid.")
        item = loads(data[offset:offset + size])
        if not isinstance(item, dict):
            raise invalid("A module frame must contain an object.")
        result.append(item)
        offset += size
    return result


def request(action: str, target_ids: list[str], parameters: dict) -> tuple[str, bytes]:
    from .registry import targets

    identifier(action)
    targets(target_ids)
    request_id = secrets.token_hex(16)
    hello = {"version": 1, "type": "hello", "host_api": 1}
    invoke = {"version": 1, "type": "invoke", "id": request_id, "action": action,
              "targets": target_ids, "parameters": parameters}
    return request_id, frame(hello) + frame(invoke)


def response(data: bytes, request_id: str, target_ids: list[str]) -> dict:
    parsed = frames(data)
    if len(parsed) != 2:
        raise invalid("The module handshake or result frame is missing.")
    hello, result = parsed
    fields(hello, {"version", "type", "protocol"})
    if (type(hello["version"]) is not int or hello["version"] != 1
            or type(hello["protocol"]) is not int or hello["protocol"] != 1
            or hello["type"] != "hello"):
        raise invalid("The module protocol handshake is unsupported.")
    return result_frame(result, request_id, target_ids)


def result_frame(result: dict, request_id: str, target_ids: list[str], version: int = 1) -> dict:
    fields(result, {"version", "type", "id", "results"})
    if (type(result["version"]) is not int or result["version"] != version
            or result["type"] != "result" or result["id"] != request_id):
        raise invalid("The module response identity is invalid.")
    return {"version": version, "id": request_id, "results": batch_results(result["results"], target_ids)}


def batch_results(items: list, target_ids: list[str]) -> list[dict]:
    if not isinstance(items, list) or len(items) != len(target_ids):
        raise invalid("The module result count does not match the target batch.")
    by_target = {}
    for item in items:
        fields(item, {"target"}, {"data", "error"})
        target = text(item["target"], 128)
        if target not in target_ids or target in by_target or ("data" in item) == ("error" in item):
            raise invalid("The module result target or outcome is invalid.")
        if "error" in item:
            fields(item["error"], {"code", "message"})
            identifier(item["error"]["code"])
            text(item["error"]["message"], 1024)
        by_target[target] = item
    return [by_target[t] for t in target_ids]
