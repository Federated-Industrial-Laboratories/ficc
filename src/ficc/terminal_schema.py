# SPDX-License-Identifier: Apache-2.0
"""Validate terminal intent and explicit stop confirmation."""

from typing import Annotated, Literal

from pydantic import Field

from .schema import Model


class TerminalRequest(Model):
    node_id: Annotated[str, Field(min_length=1, max_length=80)]
    mode: Literal["ephemeral", "tmux"]
    label: Annotated[str, Field(min_length=1, max_length=80)]
    cols: Annotated[int, Field(ge=2, le=300)] = 80
    rows: Annotated[int, Field(ge=2, le=120)] = 24
    confirm_execution: Literal[True]
    idempotency_key: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{16,80}$")]


class TerminalStop(Model):
    confirm_stop: Literal[True]
