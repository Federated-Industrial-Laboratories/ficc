# SPDX-License-Identifier: Apache-2.0
"""Bounded identities, explicit grants and immutable pairing requests."""
from typing import Annotated, Literal

from pydantic import Field, model_validator

from ..execution.spec import Identity
from ..schema import Model

Key = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Scope = Literal["discover", "inference:invoke", "inference:manage", "models:read",
                "models:transfer", "models:manage", "resources:read"]
PROTOCOL = "ficc.federation/1"


class Cluster(Model):
    key: Key
    label: Annotated[str, Field(min_length=1, max_length=80)]
    network: Key
    incarnation: Key
    service: Key
    principal: Key


class Offer(Model):
    version: Literal[1]
    purpose: Literal["ficc.pair"]
    id: Identity
    nonce: Key
    source: Cluster
    destination: Cluster
    expires: Annotated[int, Field(gt=0)]
    requested: Annotated[list[Scope], Field(min_length=1, max_length=7)]


class GrantSpec(Model):
    scopes: Annotated[list[Scope], Field(min_length=1, max_length=7)] = ["discover", "inference:invoke"]
    services: Annotated[list[Identity], Field(max_length=64)] = []
    models: Annotated[list[Identity], Field(max_length=64)] = []
    nodes: Annotated[list[Identity], Field(max_length=64)] = []
    lifetime: Annotated[int, Field(ge=60, le=2592000)] = 86400
    concurrent: Annotated[int, Field(ge=1, le=16)] = 2
    requests: Annotated[int, Field(ge=1, le=1000000)] = 1000
    transfer_bytes: Annotated[int, Field(ge=0, le=2**44)] = 0
    request_bytes: Annotated[int, Field(ge=1024, le=512*1024)] = 512*1024
    response_bytes: Annotated[int, Field(ge=1024, le=256*1024*1024)] = 64*1024*1024
    stop_on_revoke: bool = False

    @model_validator(mode="after")
    def unique(self):
        for values in (self.scopes, self.services, self.models, self.nodes):
            if len(values) != len(set(values)):
                raise ValueError("Grant selections must not contain duplicates.")
        if "models:transfer" in self.scopes and not self.transfer_bytes:
            raise ValueError("Model transfer requires an explicit finite byte allowance.")
        return self


class Configuration(Model):
    agent_directory: Annotated[str, Field(min_length=1, max_length=4096)]
    label: Annotated[str, Field(min_length=1, max_length=80)]


class Pair(Model):
    service: Key
    requested: Annotated[list[Scope], Field(min_length=1, max_length=7)] = ["discover", "inference:invoke"]


class Approval(Model):
    revision: Annotated[int, Field(ge=1)]
    grant: GrantSpec


class Request(Model):
    version: Literal[1]
    purpose: Literal["ficc.request"]
    id: Identity
    challenge: Key
    source: Key
    destination: Key
    operation: Annotated[str, Field(min_length=1, max_length=64)]
    grant: Identity | None = None
    generation: Annotated[int, Field(ge=1)] = 1
    body: dict
