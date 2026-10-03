# SPDX-License-Identifier: Apache-2.0
"""Validate explicit immutable dataset descriptions and bounded schema metadata."""

from typing import Annotated

from pydantic import Field, model_validator

from .file_schema import Entry, Id
from .schema import Model

Name = Annotated[str, Field(min_length=1, max_length=120)]


class Column(Model):
    name: Name
    type: Annotated[str, Field(min_length=1, max_length=80)]
    nullable: bool = False


class DataSchema(Model):
    fields: Annotated[list[Column], Field(max_length=256)] = []
    description: Annotated[str, Field(max_length=2048)] = ""

    @model_validator(mode="after")
    def distinct(self):
        if len({field.name for field in self.fields}) != len(self.fields):
            raise ValueError("Schema field names must be distinct.")
        return self


class Provenance(Model):
    description: Annotated[str, Field(max_length=2048)] = ""
    input_dataset_ids: Annotated[list[Id], Field(max_length=32)] = []


class CreateDataset(Model):
    name: Name
    description: Annotated[str, Field(max_length=2048)] = ""
    format: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{0,31}$")]
    data_schema: DataSchema = Field(alias="schema")
    sources: Annotated[list[Entry], Field(min_length=1, max_length=128)]
    provenance: Provenance = Field(default_factory=Provenance)
    previous_version_id: Id | None = None
