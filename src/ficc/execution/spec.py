# SPDX-License-Identifier: Apache-2.0
"""Validate execution identities, resource requests, and immutable attempt plans."""

import hashlib
import json
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_serializer, model_validator

from ..schema import Model

Identity = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Name = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,79}$")]
Count = Annotated[int, Field(ge=0, le=2**63 - 1)]
Positive = Annotated[int, Field(ge=1, le=2**63 - 1)]
Revision = Annotated[int, Field(ge=1, le=2**53 - 1)]
Device = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")]
Argument = Annotated[str, Field(max_length=16384)]
Variable = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]


def encoded(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(encoded(value)).hexdigest()


def distinct(values):
    if len(set(values)) != len(values):
        raise ValueError("Select distinct values.")
    return values


class Limits(Model):
    cpu_millis: Positive
    memory_bytes: Positive
    swap_bytes: Count
    processes: Positive
    storage_bytes: Positive
    storage_inodes: Positive
    gpu_devices: Annotated[list[Device], Field(max_length=64)]

    _devices = field_validator("gpu_devices")(distinct)

    def fits(self, ceiling: "Limits") -> bool:
        return all(getattr(self, name) <= getattr(ceiling, name) for name in (
            "cpu_millis", "memory_bytes", "swap_bytes", "processes", "storage_bytes", "storage_inodes"
        )) and set(self.gpu_devices).issubset(ceiling.gpu_devices)


class Runtime(Model):
    provider: Name
    package_digest: Digest
    image_digest: Digest
    isolation: Name
    network: Name


class Payload(Model):
    argv: Annotated[list[Argument], Field(min_length=1, max_length=256)]
    environment: Annotated[dict[Variable, Argument], Field(max_length=64)]

    @model_validator(mode="after")
    def bounded(self):
        if not self.argv[0].startswith("/") or any("\0" in item for item in [*self.argv, *self.environment.values()]):
            raise ValueError("Use an absolute container executable and arguments without null characters.")
        if len(encoded(self.model_dump())) > 65536:
            raise ValueError("The command and environment exceed 64 KiB. Use input objects for data.")
        return self


class ObjectReference(Model):
    id: Identity
    digest: Digest
    bytes: Count
    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
    delivery: Literal["local", "stream"] = "local"

    @model_serializer(mode="wrap")
    def compatible(self, serialize):
        value = serialize(self)
        if self.delivery == "local":
            value.pop("delivery", None)
        return value


class Output(Model):
    name: Name
    path: Annotated[str, Field(min_length=1, max_length=4096)]

    @field_validator("path")
    @classmethod
    def below_work_directory(cls, value):
        path = PurePosixPath(value)
        if (path.is_absolute() or str(path) != value or not path.parts
                or ".." in path.parts or any(ord(character) < 32 or ord(character) == 127 for character in value)):
            raise ValueError("Select a relative output path below the job work directory.")
        return value


class Job(Model):
    name: Annotated[str, Field(min_length=1, max_length=80)]
    runtime: Runtime
    payload: Payload
    limits: Limits
    inputs: Annotated[list[ObjectReference], Field(max_length=64)]
    outputs: Annotated[list[Output], Field(max_length=64)]
    sensitive: bool

    @model_validator(mode="after")
    def unique_inputs(self):
        distinct([item.id for item in self.inputs])
        distinct([item.name for item in self.inputs])
        distinct([item.name for item in self.outputs])
        distinct([item.path for item in self.outputs])
        return self


class Plan(Model):
    version: Literal[1]
    deployment_id: Identity
    node_id: Identity
    project_id: Identity
    subject_id: Identity
    job_id: Identity
    attempt_id: Identity
    generation: Revision
    offer_revision: Revision
    policy_revision: Count
    job: Job

    @model_validator(mode="after")
    def bounded(self):
        if len(encoded(self.model_dump())) > 131072:
            raise ValueError("The attempt plan exceeds 128 KiB. Use input objects for data.")
        return self

    def digest(self) -> str:
        return digest(self.model_dump())


class Fence(Model):
    attempt_id: Identity
    generation: Revision
    plan_digest: Digest


class Renewal(Fence):
    sequence: Revision
    expires_at: Annotated[float, Field(gt=0, allow_inf_nan=False)]


class AttemptResult(Fence):
    state: Literal["prepared", "starting", "running", "succeeded", "failed", "cancelled", "expired", "unknown", "released"]
    reason: Name | None
    exit_code: Annotated[int, Field(ge=0, le=255)] | None
    output_bytes: Count
    error_bytes: Count
    cleanup_confirmed: bool

    @model_validator(mode="after")
    def terminal_truth(self):
        if self.state == "released" and not self.cleanup_confirmed:
            raise ValueError("Release requires confirmed workload cleanup.")
        if self.state == "succeeded" and self.exit_code != 0:
            raise ValueError("Success requires an observed zero exit status.")
        return self
