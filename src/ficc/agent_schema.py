# SPDX-License-Identifier: Apache-2.0
"""Validate explicit agent launches and bounded bus messages."""

from typing import Annotated, Literal

from pydantic import Field

from .schema import Model

Identity = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Key = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{16,80}$")]
Label = Annotated[str, Field(min_length=1, max_length=80)]


class Profile(Model):
    node_id: Annotated[str, Field(min_length=1, max_length=80)]
    name: Label
    adapter: Literal["generic", "omp", "codex"]
    argv: Annotated[list[Annotated[str, Field(min_length=1, max_length=2048)]], Field(min_length=1, max_length=32)]
    workspace: Annotated[str, Field(min_length=1, max_length=4096)]


class AgentPreview(Model):
    profile_id: Identity
    label: Label
    run_id: Identity
    cols: Annotated[int, Field(ge=2, le=300)] = 100
    rows: Annotated[int, Field(ge=2, le=120)] = 30


class AgentLaunch(Model):
    preview_id: Identity
    idempotency_key: Key
    confirm_execution: Literal[True]


class AgentStop(Model):
    confirm_stop: Literal[True]


class RunCreate(Model):
    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")]
    idempotency_key: Key


class RunClose(Model):
    confirm_close: Literal[True]


class Message(Model):
    type: Literal["finding", "rank", "question", "answer", "handoff", "note", "cost"] = "note"
    body: dict
    recipient_ids: Annotated[list[Identity], Field(max_length=64)]
    delivery: Literal["inbox", "direct"] = "inbox"
    reply_to: Identity | None = None
    idempotency_key: Key
    confirm_delivery: Literal[True]
