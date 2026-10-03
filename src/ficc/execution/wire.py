# SPDX-License-Identifier: Apache-2.0
"""Validate bounded executor replies without exposing administrator filesystem paths."""

from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, model_validator

from ..schema import Model
from .offer import Offer
from .spec import AttemptResult, Count, Device, Digest, Fence, Identity, Name, Positive, Revision

MAX_REPLY = 2 * 1024 * 1024


class Error(Model):
    code: Name
    message: Annotated[str, Field(min_length=1, max_length=240)]


class Attempt(AttemptResult):
    job_id: Identity
    project_id: Identity
    offer_revision: Revision
    lease_sequence: Count
    lease_expires_at: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    ready: bool
    outcome: Literal["succeeded", "failed", "cancelled", "expired", "unknown"] | None


class Resources(Model):
    cpu_millis: Count
    memory_bytes: Count
    swap_bytes: Count
    processes: Count
    storage_bytes: Count
    storage_inodes: Count
    gpu_devices: Annotated[list[Device], Field(max_length=64)]


class SlotCapacity(Model):
    id: Name
    generation: Revision
    storage_bytes: Positive
    storage_inodes: Positive
    available: bool
    reason: Name | None


class ProviderCapacity(Model):
    id: Name
    package_digest: Digest
    available: bool
    reason: Name | None


class Capacity(Model):
    slots: Annotated[list[SlotCapacity], Field(max_length=64)]
    providers: Annotated[list[ProviderCapacity], Field(max_length=64)]
    available: Resources


class Snapshot(Model):
    installation_id: Identity
    ledger_id: Identity | None = None
    admission_version: Literal[0, 1] = 0
    deployment_id: Identity
    node_id: Identity
    maximum_lease_seconds: Annotated[int, Field(ge=5, le=30)]
    offer: Offer
    capacity: Capacity
    attempts: Annotated[list[Attempt], Field(max_length=64)]
    next: Identity | None

    @model_validator(mode="after")
    def admission_binding(self):
        if (self.admission_version == 1) != (self.ledger_id is not None):
            raise ValueError("The admission version must bind its durable ledger identity.")
        return self


class Result(Fence):
    ok: Literal[True]
    attempt: Attempt


class ReadResult(Fence):
    ok: Literal[True]
    object: Annotated[str, Field(pattern=r"^(stdout|stderr|output:[a-z][a-z0-9_.-]{0,79})$")]
    offset: Count
    data: Annotated[str, Field(max_length=1398104)]
    next_offset: Count
    total_bytes: Count
    eof: bool
    complete: bool
    identity: Digest


class InputResult(Fence):
    ok: Literal[True]
    object: Identity
    offset: Count
    bytes: Count
    digest: Digest
    complete: bool

    @model_validator(mode="after")
    def position(self):
        if self.offset > self.bytes or self.complete and self.offset != self.bytes:
            raise ValueError("The staged input offset does not match its declared size.")
        return self


class Refused(Fence):
    ok: Literal[False]
    error: Error


class Reply(Model):
    version: Literal[1]
    id: Identity
    deployment_id: Identity
    node_id: Identity


class BatchReply(Reply):
    ok: Literal[True]
    results: Annotated[list[Result | ReadResult | InputResult | Refused], Field(min_length=1, max_length=64)]


class SnapshotReply(Reply):
    ok: Literal[True]
    snapshot: Snapshot


class OfferReply(Reply):
    ok: Literal[True]
    offer: Offer


class FailureReply(Reply):
    ok: Literal[False]
    error: Error


ReplyType = BatchReply | SnapshotReply | OfferReply | FailureReply
REPLY: TypeAdapter[ReplyType] = TypeAdapter(ReplyType)


def decode(data):
    if len(data) > MAX_REPLY:
        raise ValueError("The local executor reply exceeds 2 MiB.")
    return REPLY.validate_json(data)
