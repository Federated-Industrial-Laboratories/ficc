# SPDX-License-Identifier: Apache-2.0
"""Validate bounded root references, file actions, and transfer selections."""

from typing import Annotated, Literal

from pydantic import Field

from .schema import Model

Id = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
EntryId = Annotated[str, Field(min_length=1, max_length=16384)]


class Entry(Model):
    root_id: Id
    entry_id: EntryId


class Listing(Entry):
    cursor: Annotated[str, Field(max_length=2048)] | None = None
    limit: Annotated[int, Field(ge=1, le=200)] = 100


class ContentPreview(Entry):
    limit: Annotated[int, Field(ge=1, le=65536)] = 65536


class FileOperation(Model):
    action: Literal["mkdir", "rename", "mode", "delete"]
    root_id: Id
    entries: Annotated[list[EntryId], Field(max_length=64)] = []
    parent_id: EntryId | None = None
    name: Annotated[str, Field(min_length=1, max_length=255)] | None = None
    mode: Annotated[int, Field(ge=0, le=511)] | None = None


class Confirm(Model):
    preview_id: Id
    confirm: Literal[True]


class UploadSource(Model):
    name: Annotated[str, Field(min_length=1, max_length=255)]
    size: Annotated[int, Field(ge=0, le=16*1024**3)]
    last_modified: Annotated[int, Field(ge=0)] = 0


class TransferPreview(Model):
    kind: Literal["copy", "upload", "download"]
    sources: Annotated[list[Entry | UploadSource], Field(min_length=1, max_length=64)]
    destination: Entry | None = None
    overwrite: bool = False


class Selection(Model):
    item_ids: Annotated[list[Id], Field(min_length=1, max_length=64)]


class Cancel(Selection):
    discard_partial: bool = False
