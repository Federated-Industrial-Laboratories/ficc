# SPDX-License-Identifier: Apache-2.0
"""Keep restart and administrator storage recovery separate from workload replay."""

from types import SimpleNamespace

import pytest
from test_execution_ledger import fence
from test_execution_local import admit, settle, setup

from ficc.execution import recovery
from ficc.execution.monitor import Monitor


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_restart_preserves_uncertainty_and_never_replays_an_admitted_attempt(tmp_path, count):
    s, values, provider, envelope, _clock = setup(tmp_path, count)
    try:
        admit(s, values)
        Monitor(s).recover()
        assert not provider.starts
        for value in values:
            current = s.ledger.get(value.attempt_id)
            assert current["state"] == "unknown" and current["cleanup_confirmed"]
            assert s.start(fence(value))["state"] == "unknown"
            result = s.release(fence(value))
            assert result["outcome"] == "unknown"
        assert len(envelope.stopped) == count
    finally:
        s.close()


@pytest.mark.parametrize("change", ["accepted", "active_service", "not_root", "same_generation", "account", "filesystem"])
def test_offline_remount_recovery_requires_stopped_service_and_exact_retained_identity(tmp_path, monkeypatch, change):
    s, values, _provider, _envelope, _clock = setup(tmp_path, 1)
    admit(s, values)
    asked = fence(values[0])
    record = s.ledger.get(asked.attempt_id)
    original = {"slot_id": record["slot"], "generation": 1, "mount_id": "20", "device": 7, "inode": 2,
                "filesystem_uuid": "aaaaaaaa", "uid": 10000, "gid": 10000,
                "storage_bytes": 268435456, "storage_inodes": 16384}
    with s.ledger.lock, s.ledger.db:
        record["binding"] = original
        s.ledger.save(record)
    configured = s.settings.model_copy(deep=True)
    configured.slots[0].generation = 1 if change == "same_generation" else 2
    after = {**original, "generation": configured.slots[0].generation, "mount_id": "120", "device": 8}
    if change == "account":
        after["uid"] = 10001
    if change == "filesystem":
        after["filesystem_uuid"] = "bbbbbbbb"
    s.close()
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 1000 if change == "not_root" else 0)
    monkeypatch.setattr(recovery, "properties", lambda *_args: {
        "MainPID": "123" if change == "active_service" else "0",
        "ActiveState": "active" if change == "active_service" else "inactive"})
    stopped = []
    monkeypatch.setattr(recovery, "Envelope", lambda: SimpleNamespace(stop=lambda ctx: stopped.append(ctx["unit"])))
    monkeypatch.setattr(recovery, "verify", lambda _slot, **_kwargs: after)
    if change == "accepted":
        result = recovery.recover(configured, asked, 1)
        assert result["state"] == "unknown" and result["cleanup_confirmed"]
        assert len(stopped) == 1
        from pathlib import Path

        from ficc.execution.ledger import Ledger
        ledger = Ledger(Path(configured.state), configured.installation_id)
        try:
            value = ledger.get(asked.attempt_id)
            assert value["binding"] == after and value["storage_recovery"][0]["before"] == original
            assert ledger.release(asked)["outcome"] == "unknown"
        finally:
            ledger.close()
    else:
        with pytest.raises(ValueError):
            recovery.recover(configured, asked, 1)


def test_offline_runtime_offer_upgrade_requires_released_attempts_and_revision(tmp_path, monkeypatch):
    from ficc.execution import reconfigure
    from ficc.execution.ledger import Ledger

    s, values, _provider, _envelope, _clock = setup(tmp_path, 1)
    admit(s, values)
    settings = s.settings
    s.close()
    monkeypatch.setattr(reconfigure.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reconfigure, "properties", lambda *_args: {"ActiveState": "inactive", "MainPID": "0"})
    with pytest.raises(ValueError, match="Release"):
        reconfigure.reconfigure(settings, 1)
    from pathlib import Path
    ledger = Ledger(Path(settings.state), settings.installation_id)
    try:
        value = ledger.get(values[0].attempt_id)
        value.update(state="cancelled", cleanup_confirmed=True)
        ledger.save(value)
        ledger.release(fence(values[0]))
    finally:
        ledger.close()
    with pytest.raises(ValueError, match="changed"):
        reconfigure.reconfigure(settings, 0)
    assert reconfigure.reconfigure(settings, 1)["offer"]["revision"] == 2


def test_delayed_kernel_reaping_keeps_capacity_and_does_not_replace_cancel_outcome(tmp_path):
    from ficc.execution.envelope import StopPending

    s, values, _provider, envelope, _clock = setup(tmp_path, 1)
    try:
        admit(s, values)
        stop = envelope.stop
        def pending(_context):
            raise StopPending("kernel reaping")
        envelope.stop = pending
        asked = fence(values[0])
        retained = s.request_stop(asked)
        assert not retained["cleanup_confirmed"] and retained["state"] == "prepared"
        assert s.ledger.retained() and s.cleanup_started
        envelope.stop = stop
        Monitor(s).tick()
        completed = s.ledger.get(asked.attempt_id)
        assert completed["state"] == "cancelled" and completed["cleanup_confirmed"]
        assert not s.cleanup_started
        s.release(asked)
    finally:
        s.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["inspection.json", "control/release"])
async def test_slow_payload_durability_keeps_watchdog_live_and_rechecks_revocation(tmp_path, monkeypatch, boundary):
    import asyncio
    import os
    import threading
    from pathlib import Path

    from ficc.execution import files, service

    s, values, provider, envelope, _clock = setup(tmp_path, 1)
    entered, unblock = threading.Event(), threading.Event()
    notifications = []
    server = service.Service(s)
    watch = None
    try:
        admit(s, values)
        asked = fence(values[0])
        s.start(asked)
        settle(s)
        root = Path(s.ctx(s.ledger.get(asked.attempt_id))["directory"])
        original = os.fsync
        def slow(fd):
            path = os.readlink(f"/proc/self/fd/{fd}")
            if path.startswith(str(root / boundary) + "."):
                entered.set()
                assert unblock.wait(5)
            return original(fd)
        def inspect(ctx, _prepared, pid):
            files.atomic(Path(ctx["directory"]) / "inspection.json", {"pid": pid})
            return {"pid": pid, "verified": True}
        monkeypatch.setattr(files.os, "fsync", slow)
        monkeypatch.setattr(service, "notify", notifications.append)
        s.payload_gate = inspect
        provider.states[asked.attempt_id] = {"phase": "payload", "payload_pid": 99}
        watch = asyncio.create_task(server.watch())
        assert await asyncio.to_thread(entered.wait, 2)
        before = len(notifications)
        end = asyncio.get_running_loop().time() + 2
        while len(notifications) < before + 3 and asyncio.get_running_loop().time() < end:
            await asyncio.sleep(0.02)
        assert len(notifications) >= before + 3 and not watch.done()
        assert not (root / "control/release").exists()
        assert not s.snapshot(None)["capacity"]["slots"][0]["available"]
        offered = s.offer()
        revision = offered.revision
        offered.projects = []
        offered.revision += 1
        s.ledger.save_offer(offered, revision)
        with pytest.raises(ValueError, match="lost its lease"):
            await asyncio.wait_for(watch, 2)
        assert asked.attempt_id in envelope.stopped
        unblock.set()
        with pytest.raises(ValueError):
            await asyncio.wrap_future(s.pending[asked.attempt_id][1])
        Monitor(s).tick()
        assert not (root / "control/release").exists()
        assert not s.ledger.get(asked.attempt_id).get("payload_released")
    finally:
        unblock.set()
        server.stop.set()
        if watch and not watch.done():
            await watch
        s.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_slow_storage_release_retains_capacity_and_keeps_other_leases_enforced(tmp_path, monkeypatch, failure):
    import asyncio
    import threading

    from test_execution_ledger import reading

    from ficc.execution import service
    from ficc.execution.ledger import Conflict

    s, values, provider, _envelope, clock = setup(tmp_path, 2)
    entered, unblock = threading.Event(), threading.Event()
    notifications = []
    server = service.Service(s)
    watch = release = None
    original = provider.call
    try:
        admit(s, values)
        asked = fence(values[0])
        assert s.request_stop(asked)["cleanup_confirmed"]
        def slow(identity, digest, method, rows):
            if method == "release":
                entered.set()
                assert unblock.wait(5)
                if failure:
                    raise OSError("Simulated incomplete image-tree deletion")
            return original(identity, digest, method, rows)
        provider.call = slow
        monkeypatch.setattr(service, "notify", notifications.append)
        release = asyncio.create_task(asyncio.to_thread(s.release, asked))
        assert await asyncio.to_thread(entered.wait, 2)
        watch = asyncio.create_task(server.watch())
        end = asyncio.get_running_loop().time() + 2
        while len(notifications) < 3 and asyncio.get_running_loop().time() < end:
            await asyncio.sleep(0.02)
        assert len(notifications) >= 3 and not watch.done()
        with pytest.raises(Conflict):
            await asyncio.wait_for(asyncio.to_thread(s.release, asked), 1)
        assert not s.snapshot(None)["capacity"]["slots"][0]["available"]
        assert s.ledger.get(asked.attempt_id)["state"] == "cancelled"
        clock.value = reading(31)
        end = asyncio.get_running_loop().time() + 2
        while s.ledger.get(values[1].attempt_id)["state"] != "expired" and asyncio.get_running_loop().time() < end:
            await asyncio.sleep(0.02)
        assert s.ledger.get(values[1].attempt_id)["state"] == "expired"
        unblock.set()
        if failure:
            with pytest.raises(OSError, match="incomplete image-tree"):
                await release
            assert not s.snapshot(None)["capacity"]["slots"][0]["available"]
            assert not s.releasing
            provider.call = original
            assert s.release(asked)["state"] == "released"
        else:
            assert (await release)["state"] == "released"
        assert s.snapshot(None)["capacity"]["slots"][0]["available"]
    finally:
        unblock.set()
        server.stop.set()
        if release:
            await asyncio.gather(release, return_exceptions=True)
        if watch:
            await asyncio.gather(watch, return_exceptions=True)
        s.close()
