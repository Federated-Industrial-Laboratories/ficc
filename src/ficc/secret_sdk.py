# SPDX-License-Identifier: Apache-2.0
"""Versioned trusted secret-provider contract with bounded, non-displaying values."""

import re
from dataclasses import dataclass, field

API_VERSION = 1
MAX_SECRET = 32768
ERRORS = {
    "secret_unavailable": "The secret provider, key or authenticated record is unavailable.",
    "secret_provider_unavailable": "Install exactly one matching trusted secret provider package.",
    "secret_provider_version": "The secret provider interface is unsupported or incomplete.",
    "secret_reference": "Use a secret reference of 1 to 80 letters, digits, underscores, dots or hyphens.",
    "secret_value": "Provide at most 32 KiB through a private input file or non-terminal stdin.",
    "secret_revision": "Use the current 64-character lowercase hexadecimal secret revision.",
    "secret_conflict": "The secret already exists or its revision changed. Inspect its current metadata.",
    "secret_missing": "The secret reference does not exist.",
    "secret_configuration": "The private secret provider configuration is invalid or already exists.",
    "secret_key_location": "Keep the master key in a private directory outside controller state.",
    "secret_legacy": "The private legacy source credential or its original revision key is unavailable.",
}


class SecretError(ValueError):
    """Only fixed safe diagnostics may leave the trusted secret boundary."""

    def __init__(self, code="secret_unavailable"):
        self.code = code if code in ERRORS else "secret_unavailable"
        super().__init__(ERRORS[self.code])


@dataclass(frozen=True)
class SecretValue:
    value: bytes = field(repr=False)
    revision: str


def reference(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value):
        raise SecretError("secret_reference")
    return value


def revision(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise SecretError("secret_revision")
    return value


def payload(value):
    if not isinstance(value, bytes) or len(value) > MAX_SECRET:
        raise SecretError("secret_value")
    return value
