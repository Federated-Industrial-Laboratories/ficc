# SPDX-License-Identifier: Apache-2.0
"""Keep exact byte counts across JSON clients with IEEE-754 numbers."""

from typing import Annotated

from pydantic import BeforeValidator, Field

MAX_OFFSET = 2**63 - 1
MAX_SAFE = 2**53 - 1


def integer(value):
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 19:
        value = int(value)
    if type(value) is not int or not 0 <= value <= MAX_OFFSET:
        raise ValueError("Use a non-negative integer or decimal string within the filesystem offset range.")
    return value


ByteCount = Annotated[int, BeforeValidator(integer), Field(ge=0, le=MAX_OFFSET)]


def wire(value):
    if type(value) is int and abs(value) > MAX_SAFE:
        return str(value)
    if isinstance(value, dict):
        return {key: wire(item) for key, item in value.items()}
    if isinstance(value, list):
        return [wire(item) for item in value]
    return value
