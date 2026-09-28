# SPDX-License-Identifier: Apache-2.0
"""Validate private display configuration without exposing its credentials."""

import json
import re


def document(data, maximum=4096):
    def pairs(items):
        value = dict(items)
        if len(value) != len(items):
            raise ValueError("Duplicate private display fields.")
        return value

    try:
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, (bytes, bytearray)) or len(data) > maximum:
            raise ValueError("Invalid private display size.")
        value = json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise ValueError("Invalid private display configuration.") from None
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        raise ValueError("Invalid private display version.")
    return value


def password(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9]{8}", value) is None:
        raise ValueError("Invalid private display credential.")
    return value


def ready(data, authentication="none"):
    value = document(data, 1024)
    if authentication not in {"none", "rfb-password"}:
        raise ValueError("Unsupported display authentication.")
    required = {"version", "ready"} | ({"password"} if authentication == "rfb-password" else set())
    if set(value) != required or value["ready"] is not True:
        raise ValueError("The graphics helper refused attachment.")
    return password(value["password"]) if authentication == "rfb-password" else None


def settings(data):
    value = document(data)
    if value.get("protocol") == "vnc":
        if not {"version", "protocol"} <= value.keys() or set(value) - {"version", "protocol", "password"}:
            raise ValueError("Unsupported viewer configuration.")
        return {"protocol": "vnc", **({"password": password(value["password"])} if "password" in value else {})}
    fields = {"version", "protocol", "transport", "vm_id", "username", "password", "domain", "certificate_sha256"}
    if set(value) != fields or value["protocol"] != "rdp" or value["transport"] != "vmconnect":
        raise ValueError("Unsupported viewer configuration.")
    for key, minimum, maximum in (("username", 1, 128), ("password", 1, 256), ("domain", 0, 253)):
        text = value[key]
        if (not isinstance(text, str) or not minimum <= len(text) <= maximum
                or any(ord(char) < 32 or 127 <= ord(char) <= 159 or 0xD800 <= ord(char) <= 0xDFFF for char in text)):
            raise ValueError("Invalid private display credential.")
    for key, pattern in (("vm_id", r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"),
                         ("certificate_sha256", r"[0-9a-f]{64}")):
        if not isinstance(value[key], str) or re.fullmatch(pattern, value[key]) is None:
            raise ValueError("Invalid private display identity.")
    return {key: item for key, item in value.items() if key != "version"}
