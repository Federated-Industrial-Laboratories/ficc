# SPDX-License-Identifier: Apache-2.0
"""Keep uncertain outcomes unchanged when stop, cleanup, or restart occurs."""

import asyncio
from pathlib import Path

import pytest
from test_execution_ledger import fence
from test_execution_local import admit, settle, setup

from ficc.execution import service
from ficc.execution.ledger import Ledger
from ficc.execution.monitor import Monitor


def unknown(supervisor, values, provider, envelope, *, clean, released=False):
    admit(supervisor, values)
    if released:
        for plan in values:
            supervisor.start(fence(plan))
        settle(supervisor)
        for index, plan in enumerate(values):
            provider.states[plan.attempt_id] = {"phase": "payload", "payload_pid": index + 1000}
        Monitor(supervisor).tick()
    envelope.fail_stop = not clean
    for index, plan in enumerate(values):
        provider.states[plan.attempt_id] = {"phase": "waiting", "stdout_bytes": index + 5,
                                             "stderr_bytes": index * 3 + 2}
        supervisor.finish(supervisor.ledger.get(plan.attempt_id), "runtime_outcome_unknown")
        value = supervisor.ledger.get(plan.attempt_id)
        assert value["state"] == "unknown" and value["cleanup_confirmed"] is clean
    return {plan.attempt_id: supervisor.ledger.get(plan.attempt_id) for plan in values}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_clean_unknown_stop_restart_and_release_preserve_recorded_outcome(tmp_path, count):
    s, values, provider, envelope, _clock = setup(tmp_path, count)
    try:
        before = unknown(s, values, provider, envelope, clean=True)
        stopped = list(envelope.stopped)
        changes = s.ledger.db.total_changes
        for plan in values:
            assert s.request_stop(fence(plan)) == before[plan.attempt_id]
            s.finish(before[plan.attempt_id], "cancelled")
        Monitor(s).tick()
        Monitor(s).recover()
        assert envelope.stopped == stopped and s.ledger.db.total_changes == changes
        for plan in values:
            assert s.ledger.get(plan.attempt_id) == before[plan.attempt_id]
            assert s.release(fence(plan))["outcome"] == "unknown"
        assert not provider.starts
    finally:
        s.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("operation", ["stop", "monitor", "recover"])
def test_unknown_cleanup_retry_cannot_promote_late_provider_results(tmp_path, count, operation):
    s, values, provider, envelope, _clock = setup(tmp_path, count)
    try:
        before = unknown(s, values, provider, envelope, clean=False, released=True)
        for index, plan in enumerate(values):
            assert before[plan.attempt_id]["payload_released"]
            provider.states[plan.attempt_id] = {"phase": "finished", "exit_code": index % 2,
                                                "stdout_bytes": index + 100, "stderr_bytes": 17}
            if operation == "stop":
                assert s.request_stop(fence(plan)) == before[plan.attempt_id]
        envelope.fail_stop = False
        stopped = len(envelope.stopped)
        if operation == "stop":
            for plan in values:
                s.request_stop(fence(plan))
        elif operation == "monitor":
            Monitor(s).tick()
        else:
            Monitor(s).recover()
        assert len(envelope.stopped) == stopped + count
        for plan in values:
            current = s.ledger.get(plan.attempt_id)
            assert current == {**before[plan.attempt_id], "cleanup_confirmed": True}
            assert s.release(fence(plan))["outcome"] == "unknown"
        assert len(provider.starts) == count
        assert set(provider.starts) == {plan.attempt_id for plan in values}
    finally:
        s.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_service_shutdown_leaves_clean_unknown_receipts_unchanged(tmp_path, monkeypatch, count):
    s, values, provider, envelope, _clock = setup(tmp_path, count)
    before = unknown(s, values, provider, envelope, clean=True)
    stopped = list(envelope.stopped)
    server = service.Service(s)
    notifications = []

    async def opened():
        server.stop.set()

    # Only root service setup is simulated; shutdown uses the real durable ledger.
    monkeypatch.setattr(server, "open", opened)
    monkeypatch.setattr(envelope, "supervisor", lambda _settings: None, raising=False)
    monkeypatch.setattr(service, "notify", notifications.append)
    monkeypatch.setattr(asyncio.get_running_loop(), "add_signal_handler", lambda *_args: None)
    await server.serve()
    ledger = Ledger(Path(s.settings.state), s.settings.installation_id)
    try:
        assert notifications == ["READY=1\nWATCHDOG=1"]
        assert envelope.stopped == stopped and not provider.starts
        for plan in values:
            assert ledger.get(plan.attempt_id) == before[plan.attempt_id]
            assert ledger.release(fence(plan))["outcome"] == "unknown"
    finally:
        ledger.close()
