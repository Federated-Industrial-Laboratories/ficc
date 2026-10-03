# SPDX-License-Identifier: Apache-2.0
"""Explicit owner controls and bounded local inspection configuration."""

from typing import Annotated

from pydantic import Field, field_validator

from .file_numbers import integer
from .schema import Model


class InspectionConfig(Model):
    provider: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")] | None = None
    configuration: dict = {}
    scan_on_create: bool = False
    required_new: bool = False
    memory_bytes: Annotated[int, Field(ge=134217728, le=2**63 - 1)] = 2147483648
    temp_bytes: Annotated[int, Field(ge=1048576, le=2**63 - 1)] = 268435456
    seconds: Annotated[int, Field(ge=1, le=2147483647)] = 600
    workers: Annotated[int, Field(ge=1, le=16)] = 1
    max_age_seconds: Annotated[int, Field(ge=1, le=2147483647)] = 86400

    @field_validator("memory_bytes", "temp_bytes", mode="before")
    @classmethod
    def exact(cls, value):
        return integer(value)


class SafetyChange(Model):
    revision: Annotated[int, Field(ge=1)]
    sensitive: bool
    inspection_required: bool
    quarantined: bool
    reason: Annotated[str, Field(min_length=1, max_length=1024)]


class Exemption(Model):
    revision: Annotated[int, Field(ge=1)]
    enabled: bool
    reason: Annotated[str, Field(min_length=1, max_length=1024)]
    expires_at: Annotated[float, Field(gt=0)] | None = None
