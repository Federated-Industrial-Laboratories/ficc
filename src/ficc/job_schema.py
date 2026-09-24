# SPDX-License-Identifier: Apache-2.0
"""Validate frozen managed-job requests and bounded output selections."""

import json
from typing import Annotated, Literal

from ficc_node.job_spec import validate_job
from pydantic import Field, model_validator

from .schema import Model, RefreshRequest


class JobRequest(RefreshRequest):
    action: Literal["job.submit"]
    job: dict

    @model_validator(mode="after")
    def bounded(self):
        validate_job(self.job)
        if len(set(self.node_ids)) != len(self.node_ids):
            raise ValueError("Select distinct machines.")
        if not set(self.job["gpu_reservations"]).issubset(self.node_ids):
            raise ValueError("GPU reservations must belong to selected machines.")
        if len(json.dumps(self.model_dump(), allow_nan=False).encode()) > 65536:
            raise ValueError("The serialized request exceeds 64 KiB.")
        return self


class Submission(Model):
    preview_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]


class Cancellation(RefreshRequest):
    force: bool = False

    @model_validator(mode="after")
    def distinct(self):
        if len(set(self.node_ids)) != len(self.node_ids):
            raise ValueError("Select distinct machines.")
        return self


class HelperUpgrade(Model):
    expected_fingerprint: Annotated[str, Field(min_length=16, max_length=128)]
