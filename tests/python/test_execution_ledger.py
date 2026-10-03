# SPDX-License-Identifier: Apache-2.0
"""Exercise durable attempt fencing and local consent with distinct reservations."""

import concurrent.futures
import copy

import pytest

from ficc.execution.clock import Reading
from ficc.execution.ledger import Conflict, Ledger
from ficc.execution.offer import Offer, OfferSettings, validate_offer
from ficc.execution.spec import AttemptResult, Fence, Plan, Renewal

NOW = 1700000000.0
INSTALLATION = "a" * 32


def reading(seconds=0):
    return Reading(NOW + seconds, 1_000_000_000_000 + int(seconds * 1_000_000_000),
                   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


def renew(ledger, value, seconds=0):
    lease = Renewal(**fence(value).model_dump(), sequence=1, expires_at=NOW + seconds + 30)
    return ledger.renew(lease, reading(seconds), 30)


def identity(value):
    return f"{value:032x}"


def plan(index):
    return Plan.model_validate({
        "version": 1, "deployment_id": identity(1), "node_id": identity(2),
        "project_id": identity(3), "subject_id": identity(1000 + index),
        "job_id": identity(2000 + index), "attempt_id": identity(3000 + index),
        "generation": 1, "offer_revision": 1, "policy_revision": 0,
        "job": {"name": f"Work {index}", "runtime": {"provider": "example", "package_digest": "sha256:" + "a" * 64,
            "image_digest": "sha256:" + "b" * 64, "isolation": "shared-kernel", "network": "none"},
            "payload": {"argv": ["/compute", str(index)], "environment": {"ITEM": str(index)}},
            "limits": {"cpu_millis": 1000, "memory_bytes": 1048576, "swap_bytes": 0,
                "processes": 4, "storage_bytes": 268435456, "storage_inodes": 16384,
                "gpu_devices": [f"GPU-{index}"]}, "inputs": [], "outputs": [], "sensitive": False}})


def offer(count):
    sample = plan(0)
    limits = sample.job.limits.model_dump()
    for name in ("cpu_millis", "memory_bytes", "processes", "storage_bytes", "storage_inodes"):
        limits[name] *= count
    limits["gpu_devices"] = [f"GPU-{index}" for index in range(count)]
    return Offer.model_validate({"projects": [sample.project_id], "runtimes": [sample.job.runtime.model_dump()],
        "limits": limits, "schedule_utc": [], "accept_sensitive": False, "revision": 1,
        "mode": "voluntary", "control": "active"})


def fence(value):
    return Fence(attempt_id=value.attempt_id, generation=value.generation, plan_digest=value.digest())


def result(value, state="succeeded", cleanup=True):
    return AttemptResult(**fence(value).model_dump(), state=state, reason=None,
        exit_code=0 if state == "succeeded" else None, output_bytes=17, error_bytes=0, cleanup_confirmed=cleanup)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_recovery_preserves_exact_fences_and_never_replays_uncertain_starts(tmp_path, count):
    tmp_path.chmod(0o700)
    ledger = Ledger(tmp_path, INSTALLATION)
    ledger.save_offer(offer(count), 0)
    plans = [plan(index) for index in range(count)]
    for index, value in enumerate(plans):
        ledger.reserve(value, f"slot-{index}", {"filesystem": f"fs-{index}"}, NOW)
        lease = Renewal(**fence(value).model_dump(), sequence=1, expires_at=NOW + 30)
        ledger.renew(lease, reading(), 30)
        assert ledger.start_requested(fence(value), reading())[1]
        ledger.finish(result(value, "unknown", False))
    ledger.close()
    recovered = Ledger(tmp_path, INSTALLATION)
    try:
        assert len(recovered.all()) == count
        for index, value in enumerate(plans):
            restored = recovered.reserve(value, f"slot-{index}", {"filesystem": f"fs-{index}"}, NOW + 1)
            assert restored["plan"] == value.model_dump()
            assert restored["binding"] == {"filesystem": f"fs-{index}"}
            assert recovered.start_requested(fence(value), reading(1))[1] is False
            with pytest.raises(Conflict, match="uncertain"):
                recovered.renew(Renewal(**fence(value).model_dump(), sequence=2, expires_at=NOW + 31), reading(1), 30)
            with pytest.raises(Conflict, match="unconfirmed"):
                recovered.release(fence(value))
            altered = value.model_copy(deep=True)
            altered.job.payload.argv.append("changed")
            with pytest.raises(Conflict, match="immutable plan"):
                recovered.reserve(altered, f"slot-{index}", {}, NOW + 1)
    finally:
        recovered.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_cleanup_releases_devices_but_holds_outputs_and_rejects_old_generations(tmp_path, count):
    tmp_path.chmod(0o700)
    ledger = Ledger(tmp_path, INSTALLATION)
    ledger.save_offer(offer(count), 0)
    try:
        for index in range(count):
            value = plan(index)
            ledger.reserve(value, f"slot-{index}", {}, NOW)
            renew(ledger, value)
            ledger.start_requested(fence(value), reading())
            ledger.started(fence(value), {"container": identity(4000 + index)})
            ledger.finish(result(value))
            assert not list(ledger.db.execute("SELECT id FROM devices WHERE attempt_id=?", (value.attempt_id,)))
            assert ledger.get(value.attempt_id)["slot"] == f"slot-{index}"
            with pytest.raises(Conflict, match="cannot be replaced"):
                ledger.finish(result(value, "failed"))
            ledger.release(fence(value))
            duplicate = value.model_copy(deep=True)
            duplicate.attempt_id = identity(5000 + index)
            with pytest.raises(Conflict, match="stale"):
                ledger.reserve(duplicate, f"slot-{index}", {}, NOW + 1)
            duplicate.generation += 1
            ledger.reserve(duplicate, f"slot-{index}", {}, NOW + 1)
            renew(ledger, duplicate, 1)
            assert ledger.start_requested(fence(duplicate), reading(1))[1]
            with pytest.raises(Conflict, match="current immutable attempt"):
                ledger.start_requested(Fence(attempt_id=duplicate.attempt_id, generation=1, plan_digest=value.digest()), reading(1))
        assert len(ledger.all()) == count * 2
    finally:
        ledger.close()


@pytest.mark.parametrize("resource", ["slot", "gpu", "cpu", "storage"])
def test_concurrent_admission_has_one_winner_and_no_partial_reservation(tmp_path, resource):
    tmp_path.chmod(0o700)
    ledger = Ledger(tmp_path, INSTALLATION)
    ceiling = offer(2)
    if resource == "cpu":
        ceiling.limits.cpu_millis = 1000
    if resource == "storage":
        ceiling.limits.storage_bytes = 268435456
    ledger.save_offer(ceiling, 0)
    plans = [plan(index) for index in range(2)]
    if resource == "gpu":
        plans[1].job.limits.gpu_devices = plans[0].job.limits.gpu_devices[:]

    def admit(index):
        try:
            ledger.reserve(plans[index], "shared" if resource == "slot" else f"slot-{index}", {}, NOW)
            return "reserved"
        except Conflict:
            return "refused"

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(admit, range(2)))
        assert sorted(outcomes) == ["refused", "reserved"]
        assert len(ledger.all()) == 1
        assert len(list(ledger.db.execute("SELECT id FROM devices"))) == 1
    finally:
        ledger.close()


def test_local_pause_drain_and_stop_have_distinct_authority(tmp_path):
    tmp_path.chmod(0o700)
    ledger = Ledger(tmp_path, INSTALLATION)
    initial = offer(2)
    ledger.save_offer(initial, 0)
    value = plan(0)
    ledger.reserve(value, "slot-0", {}, NOW)
    try:
        for index, state in enumerate(("paused", "draining", "stopped"), 2):
            changed = initial.model_copy(update={"control": state, "revision": index})
            ledger.save_offer(changed, index - 1)
            pending = plan(1).model_copy(update={"offer_revision": index})
            with pytest.raises(Conflict, match="local_" + state):
                ledger.reserve(pending, "slot-1", {}, NOW)
            renewal = Renewal(**fence(value).model_dump(), sequence=index, expires_at=NOW + index)
            if state == "stopped":
                with pytest.raises(Conflict, match="local_stopped"):
                    ledger.renew(renewal, reading(), 30)
            else:
                ledger.renew(renewal, reading(), 30)
        assert ledger.get(value.attempt_id)["lease_sequence"] == 3
    finally:
        ledger.close()


def test_local_owner_cannot_broaden_approved_installation():
    initial = offer(1).model_dump(exclude={"mode", "revision", "control"})
    initial["schedule_utc"] = [{"weekdays": [0], "start_minute": 600, "end_minute": 660}]
    ceiling = OfferSettings.model_validate(initial)
    for name, value in (("projects", [identity(77)]), ("schedule_utc", []), ("accept_sensitive", True)):
        changed = copy.deepcopy(initial)
        changed[name] = value
        with pytest.raises(ValueError):
            validate_offer(OfferSettings.model_validate(changed), ceiling)
    changed = copy.deepcopy(initial)
    changed["limits"]["memory_bytes"] += 1
    with pytest.raises(ValueError, match="resource limits"):
        validate_offer(OfferSettings.model_validate(changed), ceiling)
    assert offer(1).refusal(identity(3), plan(0).job.model_copy(update={"sensitive": True}), NOW) == "sensitive_data_refused"


@pytest.mark.parametrize("change", ["stopped", "reduce"])
def test_duplicate_renewal_cannot_hide_current_local_withdrawal(tmp_path, change):
    tmp_path.chmod(0o700)
    ledger = Ledger(tmp_path, INSTALLATION)
    initial = offer(2)
    ledger.save_offer(initial, 0)
    first, second = plan(0), plan(1)
    ledger.reserve(first, "slot-0", {}, NOW)
    ledger.reserve(second, "slot-1", {}, NOW)
    lease = Renewal(**fence(first).model_dump(), sequence=1, expires_at=NOW + 30)
    ledger.renew(lease, reading(), 30)
    changed = initial.model_copy(deep=True, update={"revision": 2})
    if change == "stopped":
        changed.control = "stopped"
    else:
        changed.limits.cpu_millis = 1000
    ledger.save_offer(changed, 1)
    try:
        with pytest.raises(Conflict, match="local_stopped" if change == "stopped" else "reduced local offer"):
            ledger.renew(lease, reading(1), 30)
        assert ledger.get(first.attempt_id)["lease_sequence"] == 1
    finally:
        ledger.close()
