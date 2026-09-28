# SPDX-License-Identifier: Apache-2.0
"""Validate private workspace documents and bounded panel geometry."""

import json
import math
from typing import Annotated, Any

from pydantic import Field, field_validator

from .schema import Model

Identity = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Name = Annotated[str, Field(min_length=1, max_length=80)]
Revision = Annotated[int, Field(ge=0, le=2**53 - 1)]


def bounded(value: Any, maximum: int = 262144) -> Any:
    count = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > 8192 or depth > 24:
            raise ValueError("The document exceeds its size or depth limit.")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or key in {"__proto__", "constructor", "prototype"}:
                    raise ValueError("The document contains an invalid key.")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("The document contains an invalid number.")
        elif not isinstance(item, (str, int, float, bool, type(None))):
            raise ValueError("The document contains an invalid value.")

    visit(value, 0)
    if len(json.dumps(value, allow_nan=False, ensure_ascii=False).encode()) > maximum:
        raise ValueError("The document exceeds its byte limit.")
    return value


class Instance(Model):
    id: Identity
    digest: Digest
    title: Name
    state: dict = Field(default_factory=dict)
    targets: Annotated[list[Identity], Field(max_length=64)] = Field(default_factory=list)

    @field_validator("targets")
    @classmethod
    def distinct_targets(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("Module targets must be distinct.")
        return value

    @field_validator("state")
    @classmethod
    def state_limit(cls, value):
        return bounded(value, 65536)


class WorkspaceCreate(Model):
    name: Name


class InstanceState(Model):
    revision: Revision
    state: dict

    @field_validator("state")
    @classmethod
    def state_limit(cls, value):
        return bounded(value, 65536)


class WorkspaceUpdate(Model):
    revision: Revision
    name: Name
    instances: Annotated[list[Instance], Field(max_length=64)]

    @field_validator("instances")
    @classmethod
    def distinct(cls, values):
        if len({v.id for v in values}) != len(values):
            raise ValueError("Panel identities must be distinct.")
        bounded([v.model_dump() for v in values], 524288)
        return values


class ViewUpdate(Model):
    revision: Revision
    layout: dict

    @field_validator("layout")
    @classmethod
    def layout_limit(cls, value):
        bounded(value)
        if value.get("popoutGroups"):
            raise ValueError("Use a separate workspace window.")
        panels = value.get("panels", {})
        if not isinstance(panels, dict) or len(panels) > 64:
            raise ValueError("The panel list is invalid.")
        for identity, panel in panels.items():
            if (not isinstance(panel, dict) or panel.get("id") != identity
                    or panel.get("contentComponent") != "module"):
                raise ValueError("The panel renderer is invalid.")
            if not isinstance(panel.get("params", {}), dict) or set(panel.get("params", {})) - {"instanceId"}:
                raise ValueError("The panel parameters are invalid.")
            if panel.get("params", {}).get("instanceId", identity) != identity:
                raise ValueError("The panel identity is invalid.")
        return value


class AudioPreferences(Model):
    revision: Revision
    volume: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    muted: bool


class AudioLease(Model):
    instance_id: Identity
    surface_id: Identity


class AudioLeaseOwner(Model):
    surface_id: Identity


class WorkspaceTile(Model):
    id: Identity
    workspace_id: Identity
    view_id: Identity


class SurfaceUpdate(Model):
    revision: Revision
    tiles: Annotated[list[WorkspaceTile], Field(max_length=4)]
    layout: dict

    @field_validator("tiles")
    @classmethod
    def unique(cls, values):
        for field in ("id", "workspace_id", "view_id"):
            if len({getattr(value, field) for value in values}) != len(values):
                raise ValueError("Workspace tiles must be distinct.")
        return values

    @field_validator("layout")
    @classmethod
    def layout_limit(cls, value):
        bounded(value)
        if value.get("popoutGroups") or value.get("floatingGroups"):
            raise ValueError("Open workspace windows with the host command.")
        panels = value.get("panels", {})
        if not isinstance(panels, dict) or len(panels) > 4:
            raise ValueError("The workspace tile list is invalid.")
        for identity, panel in panels.items():
            if (not isinstance(panel, dict) or panel.get("id") != identity
                    or panel.get("contentComponent") != "workspace" or panel.get("params")):
                raise ValueError("The workspace tile is invalid.")
        return value
