# SPDX-License-Identifier: Apache-2.0
"""Expire execution leases across clock adjustments, suspend, and restart."""

import math
import re
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Reading:
    wall: float
    elapsed_ns: int
    boot_id: str

    def __post_init__(self):
        if (not math.isfinite(self.wall) or self.wall <= 0
                or type(self.elapsed_ns) is not int or self.elapsed_ns < 0
                or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", self.boot_id)):
            raise ValueError("The local clock reading is invalid.")


class Clock:
    def __init__(self):
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.read()

    def read(self) -> Reading:
        # Sampling elapsed time first makes conversion conservative.
        elapsed = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        return Reading(time.time(), elapsed, self.boot_id)


def active(value: dict, now: Reading) -> bool:
    return bool(value.get("lease_sequence") and value.get("lease_boot_id") == now.boot_id
                and value["lease_expires_at"] > now.wall
                and value["lease_received_ns"] <= now.elapsed_ns < value["lease_deadline_ns"])


def deadline(expires_at: float, now: Reading, maximum_seconds: float) -> dict:
    if (not math.isfinite(maximum_seconds) or maximum_seconds <= 0
            or not math.isfinite(expires_at) or not now.wall < expires_at <= now.wall + maximum_seconds):
        raise ValueError("The execution lease is expired or exceeds the local lease limit.")
    duration_ns = int((expires_at - now.wall) * 1_000_000_000)
    if duration_ns <= 0:
        raise ValueError("The execution lease has no remaining duration.")
    return {"lease_boot_id": now.boot_id, "lease_received_ns": now.elapsed_ns,
            "lease_deadline_ns": now.elapsed_ns + duration_ns}
