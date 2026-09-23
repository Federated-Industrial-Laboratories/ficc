# SPDX-License-Identifier: Apache-2.0
"""Validate bounded API and helper messages before use."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Text = Annotated[str, Field(min_length=1, max_length=256)]
Count = Annotated[int, Field(ge=0, le=2**63 - 1)]
Number = Annotated[float, Field(ge=0, allow_inf_nan=False)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Storage(Model):
    mount: Text
    total_bytes: Count
    available_bytes: Count


class Network(Model):
    name: Text
    rx_bytes: Count
    tx_bytes: Count


class GPU(Model):
    uuid: Text
    name: Text
    memory_total_bytes: Number | None
    memory_used_bytes: Number | None
    utilization_percent: Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)] | None
    temperature_c: Annotated[float, Field(ge=-100, le=300, allow_inf_nan=False)] | None


class Resources(Model):
    cpu_percent: Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)] | None
    cpu_count: Annotated[int, Field(ge=1, le=65536)]
    load: Annotated[list[Number], Field(min_length=3, max_length=3)]
    memory_total_bytes: Count
    memory_available_bytes: Count
    uptime_seconds: Number
    storage: Annotated[list[Storage], Field(max_length=64)]
    network: Annotated[list[Network], Field(max_length=64)]
    gpus: Annotated[list[GPU], Field(max_length=64)]
    gpu_status: Literal["available", "unavailable", "unsupported"]


class Sample(Model):
    version: Literal["1"]
    boot_id: Annotated[str, Field(pattern=r"^[0-9a-f-]{36}$")]
    observed_at: Number
    monotonic_seconds: Number
    capabilities: Annotated[dict[Text, bool | Text], Field(max_length=16)]
    resources: Resources
    helper_version: Literal["1"]
    python_version: Text


class Bootstrap(Model):
    bootstrap: Annotated[str, Field(min_length=20, max_length=128)]


class PreviewRequest(Model):
    profile: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
    name: Annotated[str, Field(min_length=1, max_length=80)]


class EnrolRequest(Model):
    preview_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    expected_fingerprint: Annotated[str, Field(min_length=16, max_length=128)]
    install_helper: bool


class RefreshRequest(Model):
    node_ids: Annotated[list[Annotated[str, Field(min_length=1, max_length=80)]],
                        Field(min_length=1, max_length=64)]
