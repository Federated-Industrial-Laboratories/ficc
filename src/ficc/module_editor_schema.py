# SPDX-License-Identifier: Apache-2.0
"""Validate editor batches and explicit retained-copy removal."""

from typing import Annotated, Literal

from pydantic import Field, field_validator

from .schema import Model
from .workspace_schema import Digest, Identity

Entry = Annotated[str, Field(min_length=1, max_length=16384)]


class Context(Model):
    workspace_id: Identity
    instance_id: Identity


class Location(Model):
    root_id: Identity
    entry_id: Entry


class Listing(Context, Location):
    cursor: Annotated[str, Field(max_length=4096)] | None = None


class Read(Context):
    items: Annotated[list[Location], Field(min_length=1, max_length=64)]

    @field_validator("items")
    @classmethod
    def distinct(cls, values):
        if len({(item.root_id, item.entry_id) for item in values}) != len(values):
            raise ValueError("Select distinct files.")
        return values


class Edit(Location):
    sha256: Digest
    text: Annotated[str, Field(max_length=262144)]

    @field_validator("text")
    @classmethod
    def valid_text(cls, value):
        if "\0" in value or len(value.encode("utf-8")) > 262144:
            raise ValueError("Use UTF-8 text no larger than 256 KiB without NUL bytes.")
        return value


class Save(Context):
    accept_retained_exchange: Literal[True]
    items: Annotated[list[Edit], Field(min_length=1, max_length=64)]

    @field_validator("items")
    @classmethod
    def distinct(cls, values):
        if len({(item.root_id, item.entry_id) for item in values}) != len(values):
            raise ValueError("Select distinct files.")
        if sum(len(item.text.encode("utf-8")) for item in values) > 524288:
            raise ValueError("The edit batch exceeds 512 KiB.")
        return values


class Receipt(Context):
    operation_id: Identity


class Copy(Receipt):
    item_id: Identity
    copy_kind: Literal["original", "draft"] = Field(alias="copy")


class Cleanup(Receipt):
    item_ids: Annotated[list[Identity], Field(min_length=1, max_length=64)]
    confirm: Literal[True]
    recovered: bool = False

    @field_validator("item_ids")
    @classmethod
    def distinct(cls, values):
        if len(set(values)) != len(values):
            raise ValueError("Select distinct edit items.")
        return values
