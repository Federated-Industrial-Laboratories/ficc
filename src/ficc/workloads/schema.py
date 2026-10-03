# SPDX-License-Identifier: Apache-2.0
"""Bind submissions, durable delegations, and observed contributor attempts."""

from typing import Annotated, Literal

from pydantic import Field, field_validator, model_serializer, model_validator

from ..execution.spec import (
    AttemptResult,
    Count,
    Digest,
    Identity,
    Job,
    Name,
    Plan,
    Renewal,
    Revision,
    distinct,
)
from ..schema import Model

Timestamp = Annotated[float, Field(ge=0, allow_inf_nan=False)]
Key = Annotated[str, Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
TERMINAL = {"succeeded", "failed", "cancelled", "expired"}


class DatasetSelection(Model):
    id: Identity
    manifest_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Submission(Model):
    job: Job
    node_ids: Annotated[list[Identity], Field(min_length=1, max_length=64)]
    dataset: DatasetSelection | None = None

    _nodes = field_validator("node_ids")(distinct)

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        result = handler(self)
        if self.dataset is None:
            result.pop("dataset", None)
        return result


class Delegation(Model):
    id: Identity
    subject_id: Identity
    project_id: Identity
    credential_id: Identity
    scopes: Annotated[list[str], Field(max_length=128)]
    subject_revision: Count
    project_revision: Count
    membership_revision: Count
    policy_revision: Count
    role_revision: Count
    policy_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None
    publisher_revision: Count

    _scopes = field_validator("scopes")(distinct)


class Record(Model):
    id: Identity
    subject_id: Identity
    project_id: Identity
    actor: Identity
    key: Key
    digest: Digest
    request: Submission
    delegation: Delegation
    state: Literal["queued", "preparing", "prepared", "starting", "running", "succeeded", "failed", "cancelled", "expired", "unknown"]
    reason: Name | None
    current_attempt: Identity | None
    generation: Count
    cancelled: bool
    created_at: Timestamp
    updated_at: Timestamp
    revision: Revision

    @model_validator(mode="after")
    def ownership(self):
        if (self.subject_id, self.project_id) != (self.delegation.subject_id, self.delegation.project_id):
            raise ValueError("The job delegation belongs to another project or identity.")
        if self.updated_at < self.created_at or (self.current_attempt is None) != (self.generation == 0):
            raise ValueError("The job attempt or timestamp binding is invalid.")
        return self


class Attempt(Model):
    id: Identity
    job_id: Identity
    node_id: Identity
    installation_id: Identity
    ledger_id: Identity | None = None
    admission_version: Literal[0, 1] = 0
    plan: Plan
    lease: Renewal
    observed: AttemptResult | None
    outcome: AttemptResult | None
    start_requested: bool = False
    state: Literal["preparing", "prepared", "starting", "running", "succeeded", "failed", "cancelled", "expired", "unknown", "released", "abandoned"]
    created_at: Timestamp
    updated_at: Timestamp

    @model_validator(mode="after")
    def binding(self):
        if (self.admission_version == 1) != (self.ledger_id is not None):
            raise ValueError("The admission contract must bind one executor ledger identity.")
        if (self.id, self.job_id, self.node_id) != (self.plan.attempt_id, self.plan.job_id, self.plan.node_id):
            raise ValueError("The stored attempt does not bind its immutable plan.")
        fence = (self.id, self.plan.generation, self.plan.digest())
        if (self.lease.attempt_id, self.lease.generation, self.lease.plan_digest) != fence:
            raise ValueError("The stored lease belongs to another attempt.")
        if self.observed and (self.observed.attempt_id, self.observed.generation, self.observed.plan_digest) != fence:
            raise ValueError("The observed result belongs to another attempt.")
        if self.outcome and ((self.outcome.attempt_id, self.outcome.generation, self.outcome.plan_digest) != fence
                             or self.outcome.state not in TERMINAL | {"unknown"}):
            raise ValueError("The final outcome does not bind this attempt.")
        if self.state == "released" and (not self.observed or not self.observed.cleanup_confirmed):
            raise ValueError("Released capacity requires observed cleanup.")
        if self.updated_at < self.created_at:
            raise ValueError("The attempt timestamp order is invalid.")
        return self
