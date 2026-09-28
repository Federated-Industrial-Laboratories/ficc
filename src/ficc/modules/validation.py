# SPDX-License-Identifier: Apache-2.0
"""Validate bounded JSON values without accepting duplicate object keys."""

import json
import math
import re

from ..errors import Failure

IDENTIFIER = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON = 1024 * 1024


def invalid(message: str) -> Failure:
    return Failure("invalid_module", message, 400)


def text(value, maximum: int = 256) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise invalid("The module text is invalid or too long.")
    return value


def identifier(value) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise invalid("The module identifier is invalid.")
    return value


def digest(value) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise invalid("The module digest is invalid.")
    return value


def fields(value, required: set[str], optional: set[str] | frozenset[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise invalid("The module object has missing or unsupported fields.")
    return value


def strings(value, maximum: int = 64, length: int = 128) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise invalid("The module list exceeds the limit.")
    for item in value:
        if not text(item, length):
            raise invalid("The module list contains an empty value.")
    if len(set(value)) != len(value):
        raise invalid("The module list contains duplicate values.")
    return value


def bounded(value, depth: int = 0) -> None:
    if depth > 12:
        raise invalid("The module JSON nesting exceeds the limit.")
    if isinstance(value, dict):
        if len(value) > 256:
            raise invalid("The module object exceeds the limit.")
        for key, item in value.items():
            text(key, 240)
            bounded(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 256:
            raise invalid("The module list exceeds the limit.")
        for item in value:
            bounded(item, depth + 1)
    elif isinstance(value, str):
        text(value, 65536)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise invalid("The module number is not finite.")
    elif type(value) is int and abs(value) > 9007199254740991:
        raise invalid("The module integer exceeds the exact JSON range.")
    elif value is not None and type(value) not in (int, bool):
        raise invalid("The module JSON value is unsupported.")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise invalid("The module JSON contains duplicate keys.")
        result[key] = value
    return result


def loads(data: bytes, maximum: int = MAX_JSON):
    if not isinstance(data, bytes) or not 0 < len(data) <= maximum:
        raise invalid("The module JSON size exceeds the limit.")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object)
        bounded(value)
        return value
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise invalid("The module JSON is invalid.") from exc


def dumps(value) -> bytes:
    bounded(value)
    try:
        result = json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                            sort_keys=True, allow_nan=False).encode("utf-8")
    except (ValueError, RecursionError, OverflowError) as exc:
        raise invalid("The module JSON cannot be encoded.") from exc
    if len(result) > MAX_JSON:
        raise invalid("The module JSON size exceeds the limit.")
    return result
