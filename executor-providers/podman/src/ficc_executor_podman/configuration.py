# SPDX-License-Identifier: Apache-2.0
"""Bind the Podman provider to administrator-approved images, inputs, and device maps."""

from typing import Annotated, Literal

from ficc.execution.settings import Absolute, absolute
from ficc.execution.spec import Count, Digest, Identity, distinct
from ficc.schema import Model
from pydantic import Field, field_validator


class Image(Model):
    digest: Digest
    archive: Absolute
    archive_digest: Digest

    _archive = field_validator("archive")(absolute)


class Input(Model):
    id: Identity
    digest: Digest
    bytes: Count
    path: Absolute

    _path = field_validator("path")(absolute)


class Library(Model):
    path: Absolute
    digest: Digest

    _path = field_validator("path")(absolute)


class GPU(Model):
    cdi: Absolute
    digest: Digest
    libraries: Annotated[list[Library], Field(min_length=1, max_length=64)]

    _cdi = field_validator("cdi")(absolute)


class Configuration(Model):
    version: Literal[1]
    images: Annotated[list[Image], Field(min_length=1, max_length=64)]
    inputs: Annotated[list[Input], Field(max_length=64)]
    gpu: GPU | None

    @field_validator("images", "inputs")
    @classmethod
    def unique(cls, values):
        distinct([item.id if isinstance(item, Input) else item.digest for item in values])
        return values
