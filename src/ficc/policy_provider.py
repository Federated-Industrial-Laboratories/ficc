# SPDX-License-Identifier: Apache-2.0
"""Load an explicitly configured security provider and bind its decision envelope."""

import importlib.metadata
import json
import re
import secrets
from pathlib import Path

from .policy_packages import identifier
from .state_provider import read_private

CONFIG = "policy-provider.json"
API_VERSION = 1
MAX_ENVELOPE = 256 * 1024


def configuration(state):
    path = Path(state) / CONFIG
    if not path.exists() and not path.is_symlink():
        return None
    value = json.loads(read_private(path))
    if not isinstance(value, dict) or set(value) != {"provider", "configuration"} or not isinstance(value["configuration"], dict):
        raise ValueError("The policy provider configuration is invalid.")
    identifier(value["provider"])
    return value


def prepare(state, source, run):
    value = configuration(state)
    if value is None:
        raise ValueError("Configure a trusted policy evaluator before activation.")
    matches = list(importlib.metadata.entry_points(group="ficc.policy", name=value["provider"]))
    if len(matches) != 1:
        raise ValueError("Install exactly one trusted driver for the configured policy provider.")
    try:
        driver = matches[0].load()
        if driver.API_VERSION != API_VERSION:
            raise ValueError("Unsupported provider interface")
        return driver.prepare(value["configuration"], source, run)
    except Exception:
        raise ValueError("The trusted policy provider could not prepare the package.") from None


def request(action, authority, labels=None):
    return {"id": secrets.token_hex(16), "action": action, "authority": authority, "labels": labels or {}}


def envelope(requests, revision):
    if not 1 <= len(requests) <= 64:
        raise ValueError("Select from one to 64 policy decisions.")
    value = {"version": 1, "revision": revision, "requests": requests}
    try:
        encoded = json.dumps({"input": value}, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ValueError("The policy request must contain bounded JSON values.") from None
    if len(encoded) > MAX_ENVELOPE:
        raise ValueError("The complete policy request exceeds 256 KiB. Reduce the batch or its labels.")
    return value


def evaluate(runner, requests, revision):
    value = envelope(requests, revision)
    try:
        result = runner.evaluate(value)
    except Exception:
        raise ValueError("The trusted policy provider could not evaluate this request.") from None
    if not isinstance(result, list) or len(result) != len(requests):
        raise ValueError("The policy evaluator returned an incomplete decision batch.")
    for item, asked in zip(result, requests, strict=True):
        if (not isinstance(item, dict) or set(item) != {"id", "allow", "reason"}
                or item["id"] != asked["id"] or type(item["allow"]) is not bool
                or not isinstance(item["reason"], str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", item["reason"])):
            raise ValueError("The policy evaluator returned an invalid decision.")
    return result
