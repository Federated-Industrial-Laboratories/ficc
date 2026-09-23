# SPDX-License-Identifier: Apache-2.0
"""Verify durable node receipts, limits, identity checks, and output bounds."""

import copy
import signal
import sys
from pathlib import Path

import pytest
from ficc_node import job_runner, job_state, job_system, jobs
from ficc_node.job_spec import LOG_CAP
from test_jobs import request


@pytest.fixture
def remote(tmp_path, monkeypatch):
    base = tmp_path / "jobs"
    base.mkdir(mode=0o700)
    monkeypatch.setattr(job_state, "root", lambda: base)
    monkeypatch.setattr(jobs, "capability", lambda: {"jobs": True, "logout_persistent": False})
    archive = tmp_path / "node.pyz"
    archive.write_bytes(b"pinned helper bytes")
    monkeypatch.setattr(sys, "argv", [str(archive)])
    starts = []
    monkeypatch.setattr(jobs, "start", lambda *args: starts.append(args))

    def props(unit):
        job_id = unit.split("-")[-1].removesuffix(".service")
        value = job_state.read(base / job_id / "request.json")
        return {"Id": value["unit"], "Description": value["description"], "LoadState": "loaded",
                "ActiveState": "active", "SubState": "running", "Result": "success"}
    monkeypatch.setattr(jobs, "properties", props)
    monkeypatch.setattr(jobs, "command", lambda *args: (0, "", ""))
    return base, starts


def body(job_id="b" * 32):
    return {"version": "2", "action": "job.submit", "controller_id": "a" * 32,
            "job_id": job_id, "node_id": "node-0", "job": request()["job"]}


def call(action, **extra):
    return {"version": "2", "action": action, "controller_id": "a" * 32, "job_id": "b" * 32, **extra}


def test_node_deduplication_and_request_conflict(remote):
    base, starts = remote
    original = body()
    first = jobs.dispatch(original)
    again = jobs.dispatch(original)
    assert first["state"] == again["state"] == "running"
    assert len(starts) == 1
    changed = copy.deepcopy(original)
    changed["job"]["argv"] = ["/usr/bin/false"]
    with pytest.raises(ValueError, match="different request"):
        jobs.dispatch(changed)
    assert len(starts) == 1
    assert (base / ("b" * 32) / "request.json").stat().st_mode & 0o777 == 0o600


def test_lost_launch_ack_does_not_launch_again(remote, monkeypatch):
    base, starts = remote
    def lost(*args):
        starts.append(args)
        raise ValueError("Lost acknowledgement")
    monkeypatch.setattr(jobs, "start", lost)
    assert jobs.dispatch(body())["state"] == "unknown"
    assert jobs.dispatch(body())["state"] == "running"
    assert len(starts) == 1


def test_missing_unit_reboot_and_oom_are_not_success(remote, monkeypatch):
    base, starts = remote
    jobs.dispatch(body())
    monkeypatch.setattr(jobs, "properties", lambda unit: {"LoadState": "not-found"})
    assert jobs.dispatch(call("job.status"))["state"] == "unknown"
    monkeypatch.setattr(job_state, "boot_id", lambda: "new-boot")
    result = jobs.dispatch(call("job.status"))
    assert result["state"] == "interrupted"
    assert result["result"]["reason"] == "node_reboot"
    assert result["result"]["exit_code"] is None


def test_systemd_oom_retains_authoritative_failure(remote, monkeypatch):
    base, starts = remote
    jobs.dispatch(body())
    props = jobs.properties
    def oom(unit):
        return {**props(unit), "ActiveState": "failed", "Result": "oom-kill", "ExecMainCode": "2", "ExecMainStatus": "9"}
    monkeypatch.setattr(jobs, "properties", oom)
    result = jobs.dispatch(call("job.status"))
    assert result["state"] == "failed"
    assert result["result"]["signal"] == 9 and result["result"]["exit_code"] is None
    assert result["result"]["dropped_bytes"] is None


def test_cancel_refuses_mismatched_unit_identity(remote, monkeypatch):
    base, starts = remote
    jobs.dispatch(body())
    commands = []
    monkeypatch.setattr(jobs, "command", lambda argv: commands.append(argv))
    props = jobs.properties
    monkeypatch.setattr(jobs, "properties", lambda unit: {**props(unit), "Description": "unrelated"})
    with pytest.raises(ValueError, match="identity"):
        jobs.dispatch(call("job.cancel", force=True))
    assert commands == []


def test_gpu_conflicts_capacity_and_controller_namespace(remote, monkeypatch):
    base, starts = remote
    item = body()
    item["job"]["gpu_reservations"] = {"node-0": [{"uuid": "GPU-test", "memory_bytes": 30}]}
    monkeypatch.setattr(jobs, "gpu_metrics", lambda: ([{"uuid": "GPU-test", "memory_total_bytes": 100,
                                                       "memory_used_bytes": 80}], "available"))
    with pytest.raises(ValueError, match="free memory"):
        jobs.dispatch(item)
    assert starts == []
    item["job"]["gpu_reservations"] = {}
    jobs.dispatch(item)
    with pytest.raises(ValueError, match="active"):
        jobs.dispatch(body("c" * 32))
    stranger = body("d" * 32)
    stranger["controller_id"] = "e" * 32
    with pytest.raises(ValueError, match="another controller"):
        jobs.dispatch(stranger)
    monkeypatch.setattr(jobs, "TOTAL_LOG_CAP", LOG_CAP)
    with pytest.raises(ValueError, match="capacity"):
        jobs.dispatch(body("f" * 32))


def test_effective_limit_verification_checks_ancestors(tmp_path, monkeypatch):
    root = tmp_path / "cgroup"
    group = root / "user" / "job"
    group.mkdir(parents=True)
    files = {"memory.high": "201326592", "memory.max": "268435456",
             "memory.swap.max": "0", "pids.max": "32", "cpu.max": "100000 100000",
             "memory.oom.group": "1"}
    for name, value in files.items():
        (group / name).write_text(value)
    (group.parent / "memory.max").write_text("134217728")
    (group.parent / "cpu.max").write_text("50000 100000")
    proc = tmp_path / "proc"
    proc.write_text("0::/user/job\n")
    def path(value):
        return root if value == "/sys/fs/cgroup" else proc if value == "/proc/self/cgroup" else Path(value)
    monkeypatch.setattr(job_system, "Path", path)
    result = job_system.verify(request()["job"]["limits"])
    assert result["memory_max_bytes"] == 134217728
    assert result["cpu_percent"] == 50
    (group / "pids.max").write_text("max")
    with pytest.raises(ValueError, match="limit"):
        job_system.verify(request()["job"]["limits"])


def test_runner_bounds_output_and_preserves_exit(remote, monkeypatch):
    base, starts = remote
    item = body()
    item["job"]["argv"] = [sys.executable, "-c", "import os;os.write(1,b'x'*200000);os.write(2,b'y'*200000)"]
    jobs.dispatch(item)
    monkeypatch.setattr(job_runner, "verify", lambda limits, unit: limits)
    monkeypatch.setattr(job_runner, "settle", lambda unit: True)
    monkeypatch.setattr(job_runner, "LOG_CAP", 4096)
    before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        assert job_runner.run("b" * 32) == 0
    finally:
        for sig, handler in before.items():
            signal.signal(sig, handler)
    result = jobs.dispatch(call("job.status"))
    assert result["state"] == "succeeded" and result["result"]["exit_code"] == 0
    assert result["result"]["stdout_bytes"] + result["result"]["stderr_bytes"] == 4096
    assert result["result"]["dropped_bytes"] == 400000 - 4096
    logs = jobs.dispatch(call("job.logs", stream="stdout", offset=5, limit=10))
    assert logs["next_offset"] == 15 and logs["complete"]
    assert len(logs["data_base64"]) <= 16


def test_runner_rejects_changed_pinned_bytes(remote, monkeypatch):
    base, starts = remote
    jobs.dispatch(body())
    file = base / ("b" * 32) / "runner.pyz"
    file.write_bytes(b"changed")
    monkeypatch.setattr(job_runner, "verify", lambda *args: pytest.fail("Changed runner started"))
    assert job_runner.run("b" * 32) == 1


def test_request_and_state_links_are_refused(remote, tmp_path):
    base, starts = remote
    jobs.dispatch(body())
    path = base / ("b" * 32) / "request.json"
    saved = path.read_bytes()
    path.unlink()
    target = tmp_path / "other.json"
    target.write_bytes(saved)
    path.symlink_to(target)
    with pytest.raises(ValueError, match="private"):
        jobs.dispatch(call("job.status"))


def test_systemd_runner_uses_fixed_argv_and_required_controls(monkeypatch):
    captured = []
    monkeypatch.setattr(job_system, "command", lambda argv: (captured.append(argv) or (0, "", "")))
    item = {"job": request()["job"], "unit": "ficc-test.service", "description": "FICC:test", "job_id": "b" * 32}
    item["job"]["argv"] = ["sh", "-c", "$(touch /tmp/never-run)"]
    job_system.start(item, Path("/tmp/frozen runner.pyz"))
    argv = captured[0]
    assert "--expand-environment=no" in argv and "--property=Type=exec" in argv
    assert "--property=KillMode=control-group" in argv and "--property=MemorySwapMax=0" in argv
    assert argv[-3:] == ["/tmp/frozen runner.pyz", "--run-job", "b" * 32]
    assert not any("touch" in part for part in argv)


def test_small_completed_history_keeps_capacity_for_new_jobs(remote):
    base, starts = remote
    for index in range(64):
        item = body(f"{index:032x}")
        jobs.dispatch(item)
        path = base / item["job_id"]
        job_state.write(path / "result.json", {"state": "succeeded", "result": {"exit_code": 0, "dropped_bytes": 0}})
        output = path / "stdout"
        output.write_bytes(b"small")
        output.chmod(0o600)
    assert len(starts) == 64
    assert jobs.dispatch(body())["state"] == "running"


def test_live_truncation_count_is_unknown_before_receipt(remote):
    jobs.dispatch(body())
    assert jobs.dispatch(call("job.logs", stream="stdout", offset=0, limit=10))["dropped_bytes"] is None


def test_launch_rejection_preserves_bounded_diagnostic(remote, monkeypatch):
    def rejected(*args):
        raise ValueError("Unknown assignment: " + "x" * 1000)
    monkeypatch.setattr(jobs, "start", rejected)
    result = jobs.dispatch(body())
    assert result["state"] == "unknown"
    assert result["error"].startswith("Unknown assignment:") and len(result["error"]) == 256


def test_launch_diagnostic_survives_missing_unit_reconciliation(remote, monkeypatch):
    def rejected(*args):
        raise ValueError("Unknown assignment: unsupported property")
    monkeypatch.setattr(jobs, "start", rejected)
    first = jobs.dispatch(body())
    monkeypatch.setattr(jobs, "properties", lambda unit: {"LoadState": "not-found"})
    again = jobs.dispatch(call("job.status"))
    assert first["state"] == again["state"] == "unknown"
    assert first["error"] == again["error"] == "Unknown assignment: unsupported property"


def test_missing_job_logs_are_empty_but_state_stays_unknown(remote):
    result = jobs.dispatch(call("job.logs", stream="stdout", offset=17, limit=32))
    assert result == {"data_base64": "", "next_offset": 17, "total_bytes": 0,
                      "dropped_bytes": None, "complete": False}
    assert jobs.dispatch(call("job.status"))["state"] == "unknown"
    assert jobs.dispatch(call("job.cancel", force=False))["state"] == "unknown"


@pytest.mark.parametrize("field,value", [
    ("stream", "other"), ("stream", []), ("offset", -1), ("offset", True),
    ("offset", 2**63), ("limit", 0), ("limit", 65537), ("limit", True),
])
def test_missing_job_logs_validate_fields_first(remote, field, value):
    request = call("job.logs", stream="stdout", offset=0, limit=32)
    request[field] = value
    with pytest.raises(ValueError, match="output"):
        jobs.dispatch(request)
