# SPDX-License-Identifier: Apache-2.0
"""Keep lost execution leases expired across reconnects and local clock changes."""

from dataclasses import replace

import pytest
from test_execution_ledger import INSTALLATION, NOW, fence, offer, plan, reading, renew

from ficc.execution.clock import Clock, active
from ficc.execution.ledger import Conflict, Ledger
from ficc.execution.spec import Renewal


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_lease_deadlines_survive_restart_without_duplicate_extension(tmp_path, count):
    tmp_path.chmod(0o700)
    ledger = Ledger(tmp_path, INSTALLATION)
    ledger.save_offer(offer(count), 0)
    values = [plan(index) for index in range(count)]
    deadlines = []
    for index, value in enumerate(values):
        ledger.reserve(value, f"slot-{index}", {}, NOW)
        deadlines.append(renew(ledger, value)["lease_deadline_ns"])
    ledger.close()
    ledger = Ledger(tmp_path, INSTALLATION)
    try:
        for index, value in enumerate(values):
            duplicate = Renewal(**fence(value).model_dump(), sequence=1, expires_at=NOW + 30)
            backwards = replace(reading(20), wall=NOW - 3600)
            returned = ledger.renew(duplicate, backwards, 30)
            assert returned["lease_deadline_ns"] == deadlines[index]
            assert active(returned, backwards)
            expired = replace(reading(31), wall=NOW - 3600)
            assert not active(returned, expired)
            for sequence in (1, 2):
                request = duplicate.model_copy(update={"sequence": sequence, "expires_at": expired.wall + 30})
                with pytest.raises(Conflict, match="previous execution lease has expired"):
                    ledger.renew(request, expired, 30)
            with pytest.raises(Conflict, match="current local execution lease"):
                ledger.start_requested(fence(value), expired)
    finally:
        ledger.close()


@pytest.mark.parametrize("change", ["reboot", "elapsed_backwards", "wall_forward", "suspend"])
def test_clock_changes_do_not_revive_or_extend_work(tmp_path, change):
    tmp_path.chmod(0o700)
    ledger = Ledger(tmp_path, INSTALLATION)
    ledger.save_offer(offer(1), 0)
    value = plan(0)
    ledger.reserve(value, "slot-0", {}, NOW)
    renew(ledger, value)
    altered = {
        "reboot": replace(reading(1), boot_id="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"),
        "elapsed_backwards": replace(reading(1), elapsed_ns=1),
        "wall_forward": replace(reading(1), wall=NOW + 300),
        "suspend": reading(120),
    }[change]
    try:
        with pytest.raises(Conflict, match="current local execution lease"):
            ledger.start_requested(fence(value), altered)
        with pytest.raises(Conflict, match="previous execution lease has expired"):
            ledger.renew(Renewal(**fence(value).model_dump(), sequence=2, expires_at=altered.wall + 30), altered, 30)
        assert ledger.get(value.attempt_id)["state"] == "prepared"
    finally:
        ledger.close()


def test_start_requires_current_lease_and_unchanged_local_offer(tmp_path):
    tmp_path.chmod(0o700)
    ledger = Ledger(tmp_path, INSTALLATION)
    initial = offer(1)
    ledger.save_offer(initial, 0)
    value = plan(0)
    ledger.reserve(value, "slot-0", {}, NOW)
    try:
        with pytest.raises(Conflict, match="current local execution lease"):
            ledger.start_requested(fence(value), reading())
        renew(ledger, value)
        ledger.save_offer(initial.model_copy(update={"revision": 2, "control": "paused"}), 1)
        with pytest.raises(Conflict, match="offer changed before start"):
            ledger.start_requested(fence(value), reading(1))
        assert ledger.get(value.attempt_id)["state"] == "prepared"
    finally:
        ledger.close()


def test_linux_clock_reads_boot_identity_and_suspend_aware_elapsed_time():
    clock = Clock()
    first, second = clock.read(), clock.read()
    assert first.boot_id == second.boot_id
    assert second.elapsed_ns >= first.elapsed_ns > 0
