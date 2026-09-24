# SPDX-License-Identifier: Apache-2.0
"""Authenticate opaque root-relative byte names without exposing absolute paths."""

import base64
import hashlib
import hmac
import json
import secrets

from ficc_node.file_access import parts

from .errors import Failure


class References:
    def __init__(self, store):
        value = store.get_setting("file_reference_key", None) or secrets.token_hex(32)
        store.set_setting("file_reference_key", value)
        self.key = bytes.fromhex(value)

    def issue(self, root, reference):
        payload = json.dumps({"root": root["id"], "revision": root["revision"], "entry": reference},
                             sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.digest(self.key, payload, "sha256")
        return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")

    def resolve(self, root, value):
        try:
            if not isinstance(value, str) or len(value) > 16384:
                raise ValueError()
            raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
            data, signature = raw[:-32], raw[-32:]
            if not hmac.compare_digest(hmac.digest(self.key, data, hashlib.sha256), signature):
                raise ValueError()
            result = json.loads(data)
            if result["root"] != root["id"] or result["revision"] != root["revision"]:
                raise ValueError()
            parts(result["entry"])
            return result["entry"]
        except (ValueError, TypeError, KeyError):
            raise Failure("invalid_entry", "The entry reference is invalid. Refresh the directory.", 409) from None
