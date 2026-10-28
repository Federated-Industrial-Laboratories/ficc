# SPDX-License-Identifier: Apache-2.0
"""Durable service identity, immutable runtime selection and explicit placements."""
from typing import Annotated, Literal

from pydantic import Field, model_validator

from ..execution.spec import Identity, Limits, Name, Runtime, distinct
from ..schema import Model
from .attached import Attachment


class Placement(Model):
    node_id: Identity
    limits: Limits


class Specification(Model):
    alias: Name
    model_id: Identity
    engine: Name
    runtime: Runtime
    executable: Annotated[str, Field(pattern=r"^/[A-Za-z0-9_./-]+$", max_length=256)]
    context: Annotated[int, Field(ge=128, le=1048576)] = 4096
    concurrency: Annotated[int, Field(ge=1, le=32)] = 1
    placements: Annotated[list[Placement], Field(min_length=1, max_length=64)]
    gpu_layers: Annotated[int, Field(ge=0, le=999)] = 999
    tensor_split: Annotated[list[float], Field(max_length=64)] = []
    parallelism: Literal["tensor", "pipeline"] = "tensor"
    deadline_seconds: Annotated[int, Field(ge=1, le=600)] = 120

    @model_validator(mode="after")
    def distinct_devices(self):
        if self.runtime.network != "none":
            raise ValueError("Managed inference uses isolated executor networking.")
        chosen = [(p.node_id, gpu) for p in self.placements for gpu in p.limits.gpu_devices]
        distinct(chosen)
        for placement in self.placements:
            if self.tensor_split and (len(self.tensor_split) != len(placement.limits.gpu_devices) or any(x <= 0 for x in self.tensor_split)):
                raise ValueError("Tensor split weights must be positive and match each placement's GPU count.")
        return self


ServiceSpecification = Attachment | Specification


class Record(Model):
    id: Identity
    project_id: Identity
    subject_id: Identity
    actor: Identity
    spec: ServiceSpecification
    generation: Annotated[int, Field(ge=1)]
    desired: Literal["running", "stopped", "draining"]
    state: Literal["pending", "preparing", "loading", "ready", "draining", "stopped", "failed", "degraded", "blocked", "unknown"]
    reason: str | None
    workloads: list[Identity]
    invoke_credentials: Annotated[list[Identity], Field(max_length=512)] = []
    created_at: float
    revision: Annotated[int, Field(ge=1)]
