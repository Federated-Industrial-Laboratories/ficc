# SPDX-License-Identifier: Apache-2.0
"""Immutable model manifests; source location never substitutes for content identity."""
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from ..execution.spec import Count, Digest, Identity, distinct
from ..schema import Model


class File(Model):
    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
    digest: Digest
    bytes: Annotated[int, Field(ge=1, le=2**63 - 1)]
    url: Annotated[str, Field(max_length=4096)] | None = None

    @field_validator("url")
    @classmethod
    def source(cls, value):
        if value is not None:
            from urllib.parse import urlsplit
            parts = urlsplit(value)
            if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment or parts.query or parts.port not in (None, 443):
                raise ValueError("Use an HTTPS source without credentials, fragments or custom ports.")
        return value


class Manifest(Model):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    revision: Annotated[str, Field(min_length=1, max_length=200)]
    format: Literal["gguf", "safetensors"]
    quantization: Annotated[str, Field(max_length=80)] = "unspecified"
    licence: Annotated[str, Field(min_length=1, max_length=200)]
    source: Annotated[str, Field(max_length=200)] = "local import"
    files: Annotated[list[File], Field(min_length=1, max_length=64)]
    entrypoint: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
    capabilities: Annotated[list[Literal["chat", "embeddings"]], Field(min_length=1, max_length=2)] = ["chat"]

    @model_validator(mode="after")
    def files_complete(self):
        distinct([item.name for item in self.files])
        distinct(self.capabilities)
        if self.entrypoint not in {item.name for item in self.files}:
            raise ValueError("The entrypoint must identify a manifest file.")
        if self.format == "gguf" and not self.entrypoint.endswith(".gguf"):
            raise ValueError("GGUF models require a .gguf entrypoint.")
        if self.format == "safetensors" and not any(item.name.endswith(".safetensors") for item in self.files):
            raise ValueError("Include the immutable weight shards and tokenizer/configuration files.")
        return self


class Record(Model):
    id: Identity
    project_id: Identity
    subject_id: Identity
    manifest: Manifest
    manifest_digest: Digest
    created_at: float


class Upload(Model):
    offset: Count
    data: Annotated[str, Field(max_length=1398104)]
