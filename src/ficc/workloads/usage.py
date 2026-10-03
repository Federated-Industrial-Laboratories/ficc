# SPDX-License-Identifier: Apache-2.0
"""Account for retained project attempts, reported bytes and unreleased reservations."""

from collections import Counter

from ..file_numbers import wire
from .schema import Attempt

FIELDS = ("cpu_millis", "memory_bytes", "swap_bytes", "processes", "storage_bytes", "storage_inodes")


def report(store, project_id):
    with store.lock:
        rows = store.db.execute(
            "SELECT a.value FROM workload_attempts a JOIN workload_jobs j ON a.job_id=j.id "
            "WHERE j.project_id=:p0", (project_id,)).fetchall()
    states: Counter[str] = Counter()
    reservations = dict.fromkeys(FIELDS, 0)
    totals = {"attempts": len(rows), "unreleased_attempts": 0, "declared_input_bytes": 0,
              "reported_stdout_bytes": 0, "reported_stderr_bytes": 0, "reserved_gpu_devices": 0}
    for row in rows:
        attempt = Attempt.model_validate_json(row[0])
        observed = attempt.outcome or attempt.observed
        states[observed.state if observed else attempt.state] += 1
        totals["declared_input_bytes"] += sum(value.bytes for value in attempt.plan.job.inputs)
        if observed:
            totals["reported_stdout_bytes"] += observed.output_bytes
            totals["reported_stderr_bytes"] += observed.error_bytes
        if attempt.state != "released":
            totals["unreleased_attempts"] += 1
            for field in FIELDS:
                reservations[field] += getattr(attempt.plan.job.limits, field)
            totals["reserved_gpu_devices"] += len(attempt.plan.job.limits.gpu_devices)
    return wire({"coverage": "retained_attempts", "states": dict(states), "reservations": reservations, **totals})
