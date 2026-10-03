# SPDX-License-Identifier: Apache-2.0
"""Check real isolated decisions against current Linux process controls."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import POLICY, envelope

from ficc_policy_opa import isolation, prepare, process


def other_paths(source):
    root = source.parent / "control"
    root.mkdir(mode=0o700)
    source, run = root / "source", root / "run"
    source.mkdir(mode=0o700)
    run.mkdir(mode=0o700)
    (source / "rules.rego").write_text(POLICY)
    (source / "data.json").write_text(json.dumps({"settings": {"project": "allowed"}}))
    for path in source.iterdir():
        path.chmod(0o600)
    return source, run


def stopped(runner):
    service = runner.service
    assert service.closed and service.process.poll() is not None
    assert service.group is not None and isolation.empty(service.group)
    assert service.controls.main == service.controls.directory == -1


@pytest.mark.parametrize("count", [1, 64])
def test_live_decisions_do_not_call_manager(paths, configuration, count, monkeypatch):
    runner = prepare(configuration, *paths)
    def refuse(*args):
        raise AssertionError("A current decision called the service manager.")
    try:
        with monkeypatch.context() as patch:
            patch.setattr(process, "properties", refuse)
            patch.setattr(process, "management", refuse)
            for denied in (False, True):
                result = runner.evaluate(envelope(count, denied))
                assert [row["allow"] for row in result] == [
                    index % 2 == 0 and not denied for index in range(count)]
                assert [row["id"] for row in result] == [f"request-{index}" for index in range(count)]
    finally:
        runner.close()
    stopped(runner)


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("defect", ["tasks", "privileges", "main_exit"])
def test_current_kernel_failure_stops_only_target(paths, configuration, count, defect):
    target = prepare(configuration, *paths)
    healthy = prepare(configuration, *other_paths(paths[0]))
    child = None
    try:
        assert len(target.evaluate(envelope(count))) == count
        assert len(healthy.evaluate(envelope(count))) == count
        group = target.service.group
        assert group is not None
        if defect == "tasks":
            (group / "pids.max").write_text("63")
        elif defect == "privileges":
            child = subprocess.Popen([sys.executable, "-c", "import signal; signal.pause()"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            fields = (Path("/proc") / str(child.pid) / "status").read_text().splitlines()
            assert "NoNewPrivs:\t0" in fields
            (group / "cgroup.procs").write_text(str(child.pid))
            assert str(child.pid) in (group / "cgroup.procs").read_text().split()
        else:
            assert target.service.controls is not None
            os.kill(target.service.controls.pid, 9)
        with pytest.raises(ValueError, match="unavailable or invalid"):
            target.evaluate(envelope(count))
        stopped(target)
        result = healthy.evaluate(envelope(count))
        assert [row["allow"] for row in result] == [index % 2 == 0 for index in range(count)]
        assert not healthy.service.closed
        if child is not None:
            assert child.wait(timeout=3) < 0
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
        target.close()
        healthy.close()
    stopped(target)
    stopped(healthy)
