# SPDX-License-Identifier: Apache-2.0
"""Validate bounded contributor control messages."""

from typing import Annotated, Literal

from pydantic import Field

from .schema import Model, Sample
from .workspace_schema import Identity, Name, Revision

Secret = Annotated[str, Field(min_length=43, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
Fingerprint = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
CSR = Annotated[str, Field(min_length=100, max_length=8192)]


class Invitation(Model):
    name: Name
    mode: Literal["managed", "voluntary"]


class Claim(Model):
    secret: Secret
    node_id: Identity
    csr_pem: CSR


class Receipt(Model):
    request_id: Identity
    receipt: Secret


class Approval(Model):
    public_key: Fingerprint
    revision: Revision


class Disable(Model):
    revision: Revision


class Rotation(Model):
    request_id: Identity
    csr_pem: CSR


class Heartbeat(Model):
    version: Literal[1]
    session_id: Identity | None
    sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]
    sample: Sample
