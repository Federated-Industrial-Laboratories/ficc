# SPDX-License-Identifier: Apache-2.0
"""Validate batched local executor requests and separate transport from consent."""

import base64
import binascii
import hashlib
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, model_validator

from ..schema import Model
from .offer import OfferSettings
from .spec import Count, Digest, Fence, Identity, Plan, Renewal, Revision, distinct

INPUT_CHUNK = 1024 * 1024


class Admission(Model):
    plan: Plan
    lease: Renewal

    @model_validator(mode="after")
    def binding(self):
        if (self.lease.attempt_id, self.lease.generation, self.lease.plan_digest) != (
                self.plan.attempt_id, self.plan.generation, self.plan.digest()):
            raise ValueError("The initial lease does not bind this immutable attempt.")
        if self.lease.sequence != 1:
            raise ValueError("The initial execution lease must start at sequence one.")
        return self


class Request(Model):
    version: Literal[1]
    id: Identity


class BoundRequest(Request):
    installation_id: Identity
    ledger_id: Identity
    admission_version: Literal[1]


class Prepare(BoundRequest):
    action: Literal["prepare"]
    attempts: Annotated[list[Admission], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def unique(self):
        distinct([item.plan.attempt_id for item in self.attempts])
        return self


class RejectAbsent(BoundRequest):
    action: Literal["reject_absent"]
    plans: Annotated[list[Plan], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def unique(self):
        distinct([item.attempt_id for item in self.plans])
        return self


class ReconcileAbsent(BoundRequest):
    action: Literal["reconcile_absent"]
    plans: Annotated[list[Plan], Field(min_length=1, max_length=64)]
    acknowledge_unknown: Literal[True]

    @model_validator(mode="after")
    def unique(self):
        distinct([item.attempt_id for item in self.plans])
        return self


class Renew(Request):
    action: Literal["renew"]
    leases: Annotated[list[Renewal], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def unique(self):
        distinct([item.attempt_id for item in self.leases])
        return self


class Control(Request):
    action: Literal["start", "observe", "stop", "release"]
    attempts: Annotated[list[Fence], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def unique(self):
        distinct([item.attempt_id for item in self.attempts])
        return self


class Read(Fence):
    object: Annotated[str, Field(pattern=r"^(stdout|stderr|output:[a-z][a-z0-9_.-]{0,79})$")]
    offset: Count
    length: Annotated[int, Field(ge=1, le=1024 * 1024)]


class Collect(Request):
    action: Literal["collect"]
    reads: Annotated[list[Read], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def bounded(self):
        distinct([(item.attempt_id, item.object, item.offset) for item in self.reads])
        if sum(item.length for item in self.reads) > 1024 * 1024:
            raise ValueError("Read at most 1 MiB in each output batch. Continue with the returned offsets.")
        return self


class InputObject(Fence):
    object: Identity


class InputChunk(InputObject):
    offset: Count
    data: Annotated[str, Field(max_length=1398104)]
    digest: Digest

    def decoded(self):
        try:
            data = base64.b64decode(self.data, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("The input chunk must use valid base64.") from exc
        if len(data) > INPUT_CHUNK or base64.b64encode(data).decode("ascii") != self.data:
            raise ValueError("Use canonical base64 for at most 1 MiB of input bytes.")
        if "sha256:" + hashlib.sha256(data).hexdigest() != self.digest:
            raise ValueError("The input chunk digest does not match its bytes.")
        return data

    @model_validator(mode="after")
    def checked(self):
        self.decoded()
        return self


class InputStatus(Request):
    action: Literal["input_status"]
    objects: Annotated[list[InputObject], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def unique(self):
        distinct([(item.attempt_id, item.object) for item in self.objects])
        return self


class InputWrite(Request):
    action: Literal["input_write"]
    writes: Annotated[list[InputChunk], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def bounded(self):
        distinct([(item.attempt_id, item.object) for item in self.writes])
        if sum(len(item.decoded()) for item in self.writes) > INPUT_CHUNK:
            raise ValueError("Write at most 1 MiB in each input batch. Continue with durable offsets.")
        return self


class Snapshot(Request):
    action: Literal["snapshot"]
    after: Identity | None


class SetOffer(Request):
    action: Literal["set_offer"]
    expected_revision: Revision
    settings: OfferSettings
    control: Literal["active", "paused", "draining", "stopped"]


Message = Annotated[Prepare | RejectAbsent | ReconcileAbsent | Renew | Control | Collect | InputStatus | InputWrite | Snapshot | SetOffer,
                    Field(discriminator="action")]
MESSAGE: TypeAdapter[Message] = TypeAdapter(Message)
MAX_MESSAGE = 8 * 1024 * 1024


def decode(data: bytes):
    if len(data) > MAX_MESSAGE:
        raise ValueError("The executor control message exceeds 8 MiB. Split the batch.")
    return MESSAGE.validate_json(data)


def authorize(request, peer_uid: int, settings):
    """Socket peer credentials, not message fields, determine local authority."""
    if peer_uid == 0:
        return
    if isinstance(request, ReconcileAbsent):
        raise ValueError("Only the machine administrator can acknowledge an absent legacy attempt.")
    local_owner = settings.mode == "voluntary" and peer_uid in settings.local_owner_uids
    if isinstance(request, SetOffer):
        if not local_owner:
            raise ValueError("Only the local owner can change voluntary contribution settings.")
    elif isinstance(request, Snapshot):
        if peer_uid != settings.transport_uid and not local_owner:
            raise ValueError("This account cannot read the contributor execution state.")
    elif peer_uid != settings.transport_uid:
        raise ValueError("Only the contributor transport can request controller job operations.")
