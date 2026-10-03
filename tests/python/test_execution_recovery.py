# SPDX-License-Identifier: Apache-2.0
"""Keep restart and administrator storage recovery separate from workload replay."""

from types import SimpleNamespace

import pytest
from test_execution_ledger import fence
from test_execution_local import admit, setup

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
