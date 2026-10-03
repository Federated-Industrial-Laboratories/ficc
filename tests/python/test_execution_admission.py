# SPDX-License-Identifier: Apache-2.0
"""Keep refused admission durable and separate legacy cleanup from observed outcomes."""

import os
import shutil
from pathlib import Path

import pytest
from test_execution_ledger import NOW, fence, identity, reading, result
from test_execution_local import admit, settle, setup

from ficc.execution import envelope
from ficc.execution.ledger import Conflict, Ledger
from ficc.execution.monitor import Monitor
from ficc.execution.protocol import Admission, Read, SetOffer, authorize, decode
from ficc.execution.service import dispatch
from ficc.execution.spec import Renewal, encoded
from ficc.execution.supervisor import Supervisor
from ficc.execution.wire import REPLY, Snapshot


def bindings(supervisor):
    return {"installation_id": supervisor.settings.installation_id,
            "ledger_id": supervisor.ledger.identity, "admission_version": 1}


def message(supervisor, action, plans, **fields):
    return decode(encoded({"version": 1, "id": identity(90000), "action": action,
                           **bindings(supervisor), "plans": [item.model_dump() for item in plans], **fields}))


def admission(plan):
    return Admission(plan=plan, lease=Renewal(**fence(plan).model_dump(), sequence=1, expires_at=NOW + 30))


def reply(supervisor, request, uid=None):
    return REPLY.validate_python(dispatch(supervisor, request,
        supervisor.settings.transport_uid if uid is None else uid)).model_dump()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_host_refusal_is_durable_without_a_provider_call_and_cannot_replay(tmp_path, count):
    s, values, provider, existing_envelope, clock = setup(tmp_path, count)
    calls, original = [], provider.call

    def record(*args):
        calls.append(args[2])
        return original(*args)

    provider.call = record
    before = s.snapshot(None)["capacity"]
    current = s.ledger.offer().model_copy(update={"revision": 2, "control": "paused"})
    s.ledger.save_offer(current, 1)
    for plan in values:
        plan.offer_revision = 2
    request = decode(encoded({"version": 1, "id": identity(90000), "action": "prepare", **bindings(s),
                             "attempts": [admission(value).model_dump() for value in values]}))
    observed = reply(s, request)
    assert all(row["ok"] and row["attempt"]["state"] == "failed" and
               row["attempt"]["reason"] == "admission_rejected" and row["attempt"]["cleanup_confirmed"]
               for row in observed["results"])
    assert calls == [] and s.ledger.retained() == [] and not s.pending
    assert s.snapshot(None)["capacity"] == before
    ledger_id, settings, probe = s.ledger.identity, s.settings, s.slot_probe
    s.close()
    restored = Supervisor(settings, provider, envelope=existing_envelope, clock=clock, slot_probe=probe)
    try:
        Monitor(restored).recover()
        assert restored.ledger.identity == ledger_id and reply(restored, request) == observed
        for plan in values:
            assert restored.start(fence(plan))["state"] == "failed"
            with pytest.raises(Conflict):
                restored.renew(admission(plan).lease)
            found = restored.collect(Read(**fence(plan).model_dump(), object="stdout", offset=0, length=1))
            assert found["data"] == "" and found["total_bytes"] == 0 and found["complete"] and found["eof"]
            assert found == restored.collect(Read(**fence(plan).model_dump(), object="stdout", offset=0, length=64))
            assert found["identity"] != restored.collect(Read(**fence(plan).model_dump(), object="stderr", offset=0, length=1))["identity"]
            for object_name, offset in (("stdout", 1), ("output:absent", 0)):
                with pytest.raises(Conflict):
                    restored.collect(Read(**fence(plan).model_dump(), object=object_name, offset=offset, length=1))
            assert restored.release(fence(plan))["outcome"] == "failed"
            assert restored.prepare(admission(plan))["state"] == "released"
        assert calls == [] and len(restored.ledger.all()) == count
    finally:
        restored.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("cleanup", [True, False])
def test_provider_probe_failure_has_prior_durable_admission_and_retains_effects(tmp_path, count, cleanup):
    s, values, provider, existing_envelope, _clock = setup(tmp_path, count)
    calls, original = [], provider.call
    existing_envelope.fail_stop = not cleanup

    def fail(identity_, package, method, rows):
        calls.append(method)
        if method == "probe":
            for ctx in rows:
                record = s.ledger.get(ctx["plan"]["attempt_id"])
                assert record is not None and record["slot"] == ctx["slot"]["id"]
                assert record["lease_sequence"] == 1 and record["plan_digest"] == ctx["plan_digest"]
                directory = Path(ctx["directory"])
                directory.mkdir()
                (directory / "partial").write_text("Retained provider observation\n")
            raise ValueError("The runtime device mapping changed.")
        if method == "release":
            for ctx in rows:
                shutil.rmtree(ctx["directory"])
        return original(identity_, package, method, rows)

    provider.call = fail
    try:
        for plan in values:
            s.prepare(admission(plan))
        for _operation, future in list(s.pending.values()):
            with pytest.raises(ValueError, match="runtime device mapping changed"):
                future.result(timeout=5)
        with s.lock:
            Monitor(s).harvest()
        for plan in values:
            record = s.ledger.get(plan.attempt_id)
            assert record["state"] == ("failed" if cleanup else "unknown")
            assert record["cleanup_confirmed"] is cleanup and record["slot"] is not None
            assert not record.get("admission_rejection")
            assert (Path(s.ctx(record)["directory"]) / "partial").is_file()
            before = list(calls)
            assert s.prepare(admission(plan)) == record
            assert s.start(fence(plan)) == record and calls == before
            assert s.reject_absent(plan) == record and s.reject_absent(plan, legacy=True) == record
            if cleanup:
                assert s.release(fence(plan))["outcome"] == "failed"
            else:
                with pytest.raises(Conflict, match="unconfirmed"):
                    s.release(fence(plan))
        assert calls.count("probe") == count and "prepare" not in calls and "start" not in calls
        if not cleanup:
            with pytest.raises(ValueError, match="Stop the supervisor"):
                Monitor(s).tick()
    finally:
        s.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_reject_absent_is_batched_fenced_persistent_and_returns_existing_truth(tmp_path, count):
    s, values, provider, _envelope, _clock = setup(tmp_path, count)
    try:
        request = message(s, "reject_absent", values)
        observed = reply(s, request)
        assert len(observed["results"]) == count and all(row["ok"] for row in observed["results"])
        before = s.ledger.db.total_changes
        assert reply(s, request) == observed and s.ledger.db.total_changes == before
        changed = values[-1].model_copy(deep=True)
        changed.job.payload.argv.append("changed")
        refused = reply(s, message(s, "reject_absent", [changed]))
        assert not refused["results"][0]["ok"] and len(s.ledger.all()) == count
        for plan in values:
            assert s.prepare(admission(plan))["state"] == "failed"
            s.release(fence(plan))
            assert s.prepare(admission(plan))["state"] == "released"
        assert not provider.starts and s.ledger.retained() == []
    finally:
        s.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_legacy_cleanup_requires_root_and_preserves_unknown_through_stop_release_restart(tmp_path, count):
    s, values, provider, existing_envelope, clock = setup(tmp_path, count)
    idle = []
    existing_envelope.idle = lambda ctx: idle.append((ctx["plan"]["attempt_id"], ctx["slot"]["id"])) or {"idle": True}
    request = message(s, "reconcile_absent", values, acknowledge_unknown=True)
    for uid in (s.settings.transport_uid, 1000, 994):
        with pytest.raises(ValueError, match="machine administrator"):
            authorize(request, uid, s.settings)
    observed = reply(s, request, 0)
    assert len(idle) == count * count and all(row["ok"] and row["attempt"]["state"] == "unknown"
        and row["attempt"]["cleanup_confirmed"] and row["attempt"]["reason"] == "legacy_absence_acknowledged"
        for row in observed["results"])
    assert not provider.starts and s.ledger.retained() == []
    settings, probe = s.settings, s.slot_probe
    s.close()
    restored = Supervisor(settings, provider, envelope=existing_envelope, clock=clock, slot_probe=probe)
    try:
        Monitor(restored).recover()
        assert reply(restored, request, 0) == observed and len(idle) == count * count
        for plan in values:
            result = restored.ledger.get(plan.attempt_id)
            assert restored.request_stop(fence(plan)) == result and restored.reject_absent(plan) == result
            assert restored.start(fence(plan)) == result
            assert restored.collect(Read(**fence(plan).model_dump(), object="stderr", offset=0, length=64))["data"] == ""
            assert restored.release(fence(plan))["outcome"] == "unknown"
            assert restored.prepare(admission(plan))["state"] == "released"
        assert not existing_envelope.stopped and not provider.starts
    finally:
        restored.close()


@pytest.mark.parametrize("obstruction", ["storage", "link", "slot", "tree", "prior_generation", "foreign_node"])
def test_legacy_cleanup_refuses_incomplete_proof_without_a_tombstone(tmp_path, obstruction):
    s, values, _provider, existing_envelope, _clock = setup(tmp_path, 1)
    plan = values[0]
    existing_envelope.idle = lambda ctx: {"idle": True}
    target = Path(s.settings.slots[0].mount) / plan.attempt_id
    if obstruction == "storage":
        target.mkdir()
    elif obstruction == "link":
        target.symlink_to(tmp_path / "missing")
    elif obstruction == "slot":
        s.slot_probe = lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("Changed slot identity"))
    elif obstruction == "tree":
        existing_envelope.idle = lambda ctx: (_ for _ in ()).throw(ValueError("Workload remains active"))
    elif obstruction == "prior_generation":
        previous = plan.model_copy(update={"attempt_id": identity(90001)})
        s.ledger.reject(previous, NOW)
    else:
        plan = plan.model_copy(update={"node_id": identity(90001)})
    try:
        response = reply(s, message(s, "reconcile_absent", [plan], acknowledge_unknown=True), 0)
        assert not response["results"][0]["ok"] and s.ledger.get(plan.attempt_id) is None
    finally:
        s.close()


@pytest.mark.parametrize("field", ["installation_id", "ledger_id", "admission_version"])
def test_changed_admission_binding_is_refused_before_mutation(tmp_path, field):
    s, values, _provider, _envelope, _clock = setup(tmp_path, 1)
    try:
        raw = message(s, "reject_absent", values).model_dump()
        raw[field] = 0 if field == "admission_version" else identity(90909)
        with pytest.raises(ValueError):
            reply(s, decode(encoded(raw)))
        assert not s.ledger.all()
    finally:
        s.close()


def test_recreated_ledger_has_a_new_identity_and_refuses_the_old_binding(tmp_path):
    s, values, provider, old_envelope, clock = setup(tmp_path, 1)
    request = message(s, "reject_absent", values)
    first, settings, probe = s.ledger.identity, s.settings, s.slot_probe
    s.close()
    (Path(settings.state) / "execution.sqlite3").unlink()
    recreated = Supervisor(settings, provider, envelope=old_envelope, clock=clock, slot_probe=probe)
    try:
        assert recreated.ledger.identity != first
        with pytest.raises(Conflict, match="another installation or ledger"):
            reply(recreated, request)
        assert not recreated.ledger.all()
    finally:
        recreated.close()


def test_legacy_snapshot_is_readable_but_does_not_grant_the_new_admission_contract(tmp_path):
    s, _values, _provider, _envelope, _clock = setup(tmp_path, 1)
    try:
        current = s.snapshot(None)
        assert Snapshot.model_validate(current).admission_version == 1
        old = {key: value for key, value in current.items() if key not in {"ledger_id", "admission_version"}}
        legacy = Snapshot.model_validate(old)
        assert legacy.ledger_id is None and legacy.admission_version == 0
        for change in ({"admission_version": 1}, {"ledger_id": s.ledger.identity}):
            with pytest.raises(ValueError):
                Snapshot.model_validate({**old, **change})
    finally:
        s.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_ledger_upgrade_preserves_existing_unknown_history(tmp_path, count):
    s, values, _provider, _envelope, _clock = setup(tmp_path, count)
    for plan in values:
        s.ledger.reject(plan, NOW, observation=[{"idle": True}])
    records = s.ledger.all()
    path, installation = Path(s.settings.state), s.settings.installation_id
    with s.ledger.lock, s.ledger.db:
        s.ledger.db.execute("DELETE FROM settings WHERE key='ledger_id'")
    s.close()
    upgraded = Ledger(path, installation)
    try:
        assert len(upgraded.identity) == 32 and upgraded.all() == records
        assert all(row["state"] == "unknown" for row in upgraded.all())
    finally:
        upgraded.close()


def test_independent_idle_check_detects_actual_processes_for_a_workload_uid(monkeypatch):
    monkeypatch.setattr(envelope, "properties", lambda *args: {"LoadState": "not-found"})
    context = {"unit": "ficc-absent-unit.service", "description": "FICC absent unit",
               "cgroup": "/ficc-absent-group", "slot": {"uid": os.getuid()}}
    with pytest.raises(ValueError, match="workload account still has processes"):
        envelope.Envelope().idle(context)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("state", ["prepared", "running"])
def test_deliberate_local_stop_records_cancellation_and_preserves_observed_outcomes(tmp_path, count, state):
    s, values, provider, _envelope, _clock = setup(tmp_path, count)
    try:
        admit(s, values)
        if state == "running":
            for plan in values:
                s.start(fence(plan))
            settle(s)
            for plan in values:
                s.ledger.started(fence(plan), {"fixture": True})
                s.ledger.annotate(fence(plan), payload_released=True)
                provider.states[plan.attempt_id] = {"phase": "payload", "payload_pid": 1}
        before = s.ledger.offer()
        command = SetOffer(version=1, id=identity(90000), action="set_offer", expected_revision=before.revision,
            settings=before.model_dump(exclude={"revision", "mode", "control"}), control="stopped")
        s.set_offer(command)
        assert all(s.ledger.get(plan.attempt_id)["pending_stop"] == "cancelled" for plan in values)
        Monitor(s).tick()
        for plan in values:
            record = s.ledger.get(plan.attempt_id)
            assert record["state"] == "cancelled" and record["cleanup_confirmed"]
            assert record["reason"] == "cancelled" and s.release(fence(plan))["outcome"] == "cancelled"
        assert s.ledger.offer().control == "stopped"
    finally:
        s.close()


def test_expiry_stays_expired_without_deliberate_local_stop(tmp_path):
    s, values, _provider, _envelope, clock = setup(tmp_path, 1)
    try:
        admit(s, values)
        clock.value = reading(31)
        Monitor(s).tick()
        assert s.ledger.get(values[0].attempt_id)["state"] == "expired"
    finally:
        s.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("outcome", ["unknown", "failed", "succeeded"])
def test_local_offer_stop_does_not_rewrite_completed_or_unknown_truth(tmp_path, count, outcome):
    s, values, _provider, old_envelope, _clock = setup(tmp_path, count)
    try:
        admit(s, values)
        for plan in values:
            s.ledger.finish(result(plan, outcome))
        before = s.ledger.all()
        offer = s.ledger.offer()
        s.set_offer(SetOffer(version=1, id=identity(90000), action="set_offer", expected_revision=offer.revision,
            settings=offer.model_dump(exclude={"revision", "mode", "control"}), control="stopped"))
        Monitor(s).tick()
        assert s.ledger.all() == before and not old_envelope.stopped
    finally:
        s.close()
