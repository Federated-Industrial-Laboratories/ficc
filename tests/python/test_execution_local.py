# SPDX-License-Identifier: Apache-2.0
"""Exercise local lifecycle and lease behavior with explicitly simulated OS boundaries."""

import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_execution_ledger import NOW, fence, identity, offer, plan, reading
from test_execution_settings import settings

from ficc.execution.monitor import Monitor
from ficc.execution.protocol import Admission, Read
from ficc.execution.settings import Settings
from ficc.execution.spec import Renewal
from ficc.execution.supervisor import Supervisor
from ficc.execution.wire import Snapshot


class FakeProvider:
    def __init__(self):
        self.states, self.starts = {}, []
        self.block = None

    def call(self, _identity, _digest, method, rows):
        from ficc.execution.outputs import collect
        result = []
        for ctx in rows:
            key = ctx["plan"]["attempt_id"]
            root = Path(ctx["directory"])
            if method == "probe":
                value = {"ready": True}
            elif method == "prepare":
                root.mkdir()
                (root / "control").mkdir()
                (root / "runtime/work").mkdir(parents=True)
                if self.block:
                    self.block.wait(5)
                ctx["check"]()
                self.states[key] = {"phase": "waiting"}
                value = {"argv": [], "devices": [], "mounts": [], "barrier": "/simulated",
                         "positive_devices": [], "negative_devices": []}
            elif method == "start":
                self.starts.append(key)
                self.states[key] = {"phase": "ready", "device_probe": []}
                value = ctx["prepared"]
            elif method in {"observe", "stop"}:
                value = self.states[key]
            elif method == "collect":
                value = collect(ctx, Read.model_validate(ctx["read"]), ctx["cleanup_confirmed"])
            elif method == "release":
                value = {"released": True}
            else:
                raise AssertionError(method)
            result.append(value)
        return result


class FakeEnvelope:
    def __init__(self):
        self.stopped = []
        self.fail_stop = False

    def launch(self, ctx, prepared):
        assert prepared["argv"] == []

    def inspect(self, _ctx):
        return {"LoadState": "loaded", "ActiveState": "active", "ExecMainExitTimestampMonotonic": "0"}

    def controls(self, ctx, _prepared):
        return {"cgroup": ctx["cgroup"]}

    def stop(self, ctx):
        self.stopped.append(ctx["plan"]["attempt_id"])
        if self.fail_stop:
            raise ValueError("Simulated unconfirmed process cleanup")
        return {}


def setup(tmp_path, count):
    value = settings()
    initial = offer(count)
    projects = [identity(5000 + index) for index in range(count)]
    initial.projects = projects
    value.update(state=str(tmp_path / "state"), sockets=str(tmp_path / "sockets"),
                 initial_offer=initial.model_dump(),
                 ceiling=initial.model_dump(exclude={"mode", "control", "revision"}))
    Path(value["state"]).mkdir(mode=0o700)
    value["slots"] = []
    for index in range(count):
        path = tmp_path / f"slot-{index}"
        path.mkdir()
        value["slots"].append({"id": f"slot-{index:02d}", "generation": 1, "mount": str(path),
            "filesystem_uuid": f"aaaaaaaa-aaaa-aaaa-aaaa-{index:012d}", "account": f"work-{index}",
            "uid": 10000 + index, "gid": 10000 + index, "storage_bytes": 268435456, "storage_inodes": 16384})
    configured = Settings.model_validate(value)
    clock = SimpleNamespace(value=reading())
    clock.read = lambda: clock.value
    provider, envelope = FakeProvider(), FakeEnvelope()
    def probe(slot, previous=None, *, idle=False):
        bound = {"device": Path(slot.mount).stat().st_dev, "slot": slot.id, "generation": slot.generation}
        assert previous is None or previous == bound
        return bound
    supervisor = Supervisor(configured, provider, envelope=envelope, clock=clock, slot_probe=probe,
                            payload_gate=lambda _ctx, _prepared, pid: {"pid": pid, "verified": True})
    Monitor(supervisor).recover()
    plans = [plan(index).model_copy(update={"project_id": projects[index]}) for index in range(count)]
    return supervisor, plans, provider, envelope, clock


def admit(supervisor, values):
    for value in values:
        request = Admission(plan=value, lease=Renewal(**fence(value).model_dump(), sequence=1, expires_at=NOW + 30))
        supervisor.prepare(request)
    settle(supervisor)


def settle(supervisor):
    end = time.monotonic() + 5
    while supervisor.pending and time.monotonic() < end:
        Monitor(supervisor).tick()
        time.sleep(0.002)
    assert not supervisor.pending


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distinct_local_attempts_complete_or_fail_without_crossing_reservations(tmp_path, count):
    s, values, provider, envelope, _clock = setup(tmp_path, count)
    try:
        admit(s, values)
        snapshot = Snapshot.model_validate(s.snapshot(None))
        assert snapshot.maximum_lease_seconds == 30
        assert len(snapshot.attempts) == count and all(item.ready for item in snapshot.attempts)
        assert snapshot.capacity.available.cpu_millis == 0
        for value in values:
            assert s.start(fence(value))["state"] == "starting"
        settle(s)
        for index, value in enumerate(values):
            provider.states[value.attempt_id] = {"phase": "payload", "payload_pid": index + 10}
        Monitor(s).tick()
        assert all(s.ledger.get(value.attempt_id)["state"] == "running" for value in values)
        for index, value in enumerate(values):
            record = s.ledger.get(value.attempt_id)
            path = Path(s.ctx(record)["directory"]) / "runtime/stdout"
            path.write_text(f"result-{index}\n")
            provider.states[value.attempt_id] = {"phase": "finished", "exit_code": index % 3,
                                                "stdout_bytes": path.stat().st_size, "stderr_bytes": 0}
        Monitor(s).tick()
        for index, value in enumerate(values):
            result = s.ledger.get(value.attempt_id)
            assert result["state"] == ("succeeded" if index % 3 == 0 else "failed")
            assert result["cleanup_confirmed"]
            data = s.collect(Read(**fence(value).model_dump(), object="stdout", offset=0, length=1024))
            import base64
            assert base64.b64decode(data["data"]) == f"result-{index}\n".encode()
            assert data["complete"]
            released = s.release(fence(value))
            assert released["outcome"] == result["state"] and released["slot"] is None
        assert set(envelope.stopped) == {value.attempt_id for value in values}
        assert len(provider.starts) == count
    finally:
        s.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_duplicate_admission_and_renewal_do_not_extend_a_persisted_deadline(tmp_path, count):
    s, values, provider, _envelope, clock = setup(tmp_path, count)
    try:
        admit(s, values)
        clock.value = reading(15)
        for value in values:
            before = s.ledger.get(value.attempt_id)
            duplicate = Admission(plan=value, lease=Renewal(**fence(value).model_dump(), sequence=1, expires_at=NOW + 40))
            assert s.prepare(duplicate)["lease_deadline_ns"] == before["lease_deadline_ns"]
            assert s.renew(Renewal(**fence(value).model_dump(), sequence=1, expires_at=NOW + 30))["lease_deadline_ns"] == before["lease_deadline_ns"]
        clock.value = reading(31)
        Monitor(s).tick()
        assert not provider.starts
        assert all(s.ledger.get(value.attempt_id)["state"] == "expired" for value in values)
    finally:
        s.close()


def test_failed_first_lease_retains_rejection_without_gpu_reservation(tmp_path):
    s, values, _provider, _envelope, _clock = setup(tmp_path, 1)
    try:
        value = values[0]
        request = Admission(plan=value, lease=Renewal(**fence(value).model_dump(), sequence=1, expires_at=NOW - 1))
        result = s.prepare(request)
        assert result["state"] == "failed" and result["reason"] == "admission_rejected"
        assert result["slot"] is None and result["cleanup_confirmed"]
        assert s.ledger.get(value.attempt_id) == result
        assert s.ledger.retained() == []
    finally:
        s.close()


@pytest.mark.parametrize("change", ["expiry", "stop", "offer_withdrawal"])
def test_preparation_cannot_start_after_its_authority_is_lost(tmp_path, change):
    import threading
    s, values, provider, _envelope, clock = setup(tmp_path, 1)
    provider.block = threading.Event()
    try:
        value = values[0]
        s.prepare(Admission(plan=value, lease=Renewal(**fence(value).model_dump(), sequence=1, expires_at=NOW + 30)))
        if change == "expiry":
            clock.value = reading(31)
        elif change == "stop":
            s.request_stop(fence(value))
        else:
            initial = s.ledger.offer()
            initial.projects = []
            initial.revision += 1
            s.ledger.save_offer(initial, 1)
        Monitor(s).tick()
        provider.block.set()
        settle(s)
        result = s.ledger.get(value.attempt_id)
        assert result["state"] in {"failed", "expired", "cancelled"}
        assert not provider.starts
        with pytest.raises(ValueError):
            s.renew(Renewal(**fence(value).model_dump(), sequence=2, expires_at=clock.read().wall + 30))
        assert result["cleanup_confirmed"]
    finally:
        provider.block.set()
        s.close()


def test_unconfirmed_cleanup_quarantines_capacity_and_stops_monitor_progress(tmp_path):
    s, values, _provider, envelope, clock = setup(tmp_path, 1)
    try:
        admit(s, values)
        envelope.fail_stop = True
        clock.value = reading(31)
        Monitor(s).tick()
        record = s.ledger.get(values[0].attempt_id)
        assert record["state"] == "unknown" and not record["cleanup_confirmed"]
        with pytest.raises(ValueError, match="Stop the supervisor"):
            Monitor(s).tick()
        with pytest.raises(ValueError):
            s.release(fence(values[0]))
        assert not s.snapshot(None)["capacity"]["slots"][0]["available"]
    finally:
        s.close()
