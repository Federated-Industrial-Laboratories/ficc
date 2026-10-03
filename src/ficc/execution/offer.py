# SPDX-License-Identifier: Apache-2.0
"""Intersect local consent, approved runtimes, schedules, and resource ceilings."""

from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from ..schema import Model
from .spec import Identity, Job, Limits, Revision, Runtime, distinct


class Window(Model):
    weekdays: Annotated[list[Annotated[int, Field(ge=0, le=6)]], Field(min_length=1, max_length=7)]
    start_minute: Annotated[int, Field(ge=0, le=1439)]
    end_minute: Annotated[int, Field(ge=1, le=1440)]

    _days = field_validator("weekdays")(distinct)

    @model_validator(mode="after")
    def ordered(self):
        if self.start_minute >= self.end_minute:
            raise ValueError("Each UTC window must end after it starts. Split a window that crosses midnight.")
        return self

    def contains(self, now: float) -> bool:
        date = datetime.fromtimestamp(now, timezone.utc)
        return date.weekday() in self.weekdays and self.start_minute <= date.hour * 60 + date.minute < self.end_minute


class OfferSettings(Model):
    projects: Annotated[list[Identity], Field(max_length=64)]
    runtimes: Annotated[list[Runtime], Field(max_length=64)]
    limits: Limits
    schedule_utc: Annotated[list[Window], Field(max_length=64)]
    accept_sensitive: bool

    _projects = field_validator("projects")(distinct)

    @model_validator(mode="after")
    def unique_runtimes(self):
        distinct([item.model_dump_json() for item in self.runtimes])
        return self


class Offer(OfferSettings):
    revision: Revision
    mode: Literal["managed", "voluntary"]
    control: Literal["active", "paused", "draining", "stopped"]

    def refusal(self, project: str, job: Job, now: float, *, continuing: bool = False) -> str | None:
        if self.control == "stopped" or not continuing and self.control != "active":
            return "local_" + self.control
        if project not in self.projects:
            return "local_project_refused"
        if job.runtime not in self.runtimes:
            return "local_runtime_refused"
        if not job.limits.fits(self.limits):
            return "local_resource_limit"
        if self.schedule_utc and not any(window.contains(now) for window in self.schedule_utc):
            return "outside_local_schedule"
        if job.sensitive and (self.mode != "managed" or not self.accept_sensitive):
            return "sensitive_data_refused"
        return None


def validate_offer(settings: OfferSettings, ceiling: OfferSettings):
    """A local owner cannot broaden the machine administrator's installation limits."""
    if not set(settings.projects).issubset(ceiling.projects):
        raise ValueError("Select projects approved by the machine administrator.")
    if any(runtime not in ceiling.runtimes for runtime in settings.runtimes):
        raise ValueError("Select runtimes approved by the machine administrator.")
    if not settings.limits.fits(ceiling.limits):
        raise ValueError("The offer exceeds the machine administrator's resource limits.")
    if settings.accept_sensitive and not ceiling.accept_sensitive:
        raise ValueError("The machine administrator has not approved sensitive data.")
    if ceiling.schedule_utc:
        approved = {(day, minute) for window in ceiling.schedule_utc for day in window.weekdays
                    for minute in range(window.start_minute, window.end_minute)}
        proposed = ({(day, minute) for window in settings.schedule_utc for day in window.weekdays
                     for minute in range(window.start_minute, window.end_minute)} if settings.schedule_utc else
                    {(day, minute) for day in range(7) for minute in range(1440)})
        if not proposed.issubset(approved):
            raise ValueError("The offer exceeds the machine administrator's approved schedule.")
