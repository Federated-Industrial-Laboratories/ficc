# SPDX-License-Identifier: Apache-2.0
"""Public connection, registered-query and bounded pipeline requests."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .dataset_schema import Name
from .file_numbers import ByteCount
from .file_schema import Entry, Id
from .schema import Model

Secret = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$")]


class Endpoint(Model):
    host: Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$")]
    port: Annotated[int, Field(ge=1, le=65535)]
    addresses: Annotated[list[str], Field(min_length=1, max_length=16)]
    ca_pem: Annotated[str, Field(min_length=1, max_length=32768)]
    private_network: bool = False
    fixed_address: str | None = None


class Connection(Model):
    name: Name
    provider: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,39}$")]
    configuration: dict = {}
    source: Entry | None = None
    endpoint: Endpoint | None = None
    read_secret: Secret | None = None
    write_secret: Secret | None = None
    permissions: Annotated[list[Literal["read", "export", "write"]], Field(min_length=1, max_length=3)] = ["read"]


class Parameter(Model):
    name: Annotated[str, Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")]
    type: Literal["string", "integer", "number", "boolean"]
    nullable: bool = False


class RegisteredQuery(Model):
    name: Name
    mode: Literal["read", "write"] = "read"
    specification: dict
    parameters: Annotated[list[Parameter], Field(max_length=64)] = []

    @model_validator(mode="after")
    def distinct(self):
        if len({item.name for item in self.parameters}) != len(self.parameters):
            raise ValueError("Query parameter names must be distinct.")
        return self


class Values(Model):
    parameters: dict = {}


class Run(Values):
    action: Literal["export", "write"] = "export"
    destination: Entry | None = None
    filename: Annotated[str, Field(min_length=1, max_length=255)] | None = None
    dataset_name: Name | None = None
    format: Literal["csv", "arrow", "parquet", "original"] = "csv"


class SourceLimits(Model):
    memory_bytes: Annotated[int, Field(ge=134217728)] = 536870912
    seconds: Annotated[int, Field(ge=1)] = 3600
    export_bytes: ByteCount | None = 64 * 1024**3
    free_bytes: ByteCount = 256 * 1024**2
    workers: Annotated[int, Field(ge=1, le=32)] = 4


class Describe(Model):
    resource: Annotated[str, Field(min_length=1, max_length=2048)]


class Enabled(Model):
    enabled: bool
    revision: Annotated[int, Field(ge=1)]


class CreateUpload(Model):
    key: Annotated[str, Field(min_length=1, max_length=1024)]
    dataset_id: Id
    file_index: Annotated[int, Field(ge=0, le=127)] = 0


class UploadOperation(Model):
    operation: Literal["status", "part", "complete", "abort", "reconcile"]
    part_number: Annotated[int, Field(ge=1, le=10000)] | None = None
    cursor: Annotated[int, Field(ge=0, le=10000)] = 0
