# SPDX-License-Identifier: Apache-2.0
"""Define the bounded information approved for agent observation."""

import re
from typing import Annotated

from pydantic import Field

from .schema import Model, Number, Resources
from .settings import MAX_NODES

NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
NodeId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")]


class InventoryNode(Model):
    id: NodeId
    name: Annotated[str, Field(min_length=1, max_length=80)]
    state: Annotated[str, Field(min_length=1, max_length=32)]
    last_seen: Number | None
    sample_age_seconds: Number | None
    stale: bool


class Inventory(Model):
    nodes: Annotated[list[InventoryNode], Field(max_length=MAX_NODES)]


class Reading(Model):
    node_id: NodeId
    resources: Resources | None
    last_seen: Number | None
    sample_age_seconds: Number | None
    stale: bool
