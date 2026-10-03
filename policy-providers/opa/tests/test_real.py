# SPDX-License-Identifier: Apache-2.0
"""Qualify real OPA compilation, decisions, resource limits and complete cleanup."""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from conftest import envelope

from ficc_policy_opa import isolation, prepare, process
from ficc_policy_opa import runner as runner_module


def stopped(runner) -> None:
    assert runner.service.closed
    assert runner.service.process.poll() is not None
    assert runner.service.group is not None and isolation.empty(runner.service.group)


@pytest.mark.parametrize("count", [1, 64])
def test_actual_decisions_and_controls(paths, configuration, count, monkeypatch):
    source, run = paths
    monkeypatch.setenv("FICC_TEST_SECRET", "must-not-enter")
    runner = prepare(configuration, source, run)
    try:
        for denied in (False, True):
            request = envelope(count, denied)
            result = runner.evaluate(request)
            assert result == [{"id": item["id"], "allow": index % 2 == 0 and not denied,
                               "reason": "allowed" if index % 2 == 0 and not denied else "denied"}
                              for index, item in enumerate(request["requests"])]
        group = runner.service.group
        assert group is not None
        limits = {name: (group / name).read_text().strip() for name in
                  ("memory.max", "memory.swap.max", "pids.max", "cpu.max")}
        assert limits["memory.max"] == "536870912"
        assert limits["memory.swap.max"] == "0"
        assert limits["pids.max"] == "64"
        assert runner.socket.stat().st_mode & 0o777 == 0o600
        evaluator_pids = []
        for pid in (group / "cgroup.procs").read_text().split():
            root = Path("/proc") / pid
            if (root / "comm").read_text().strip() != "opa":
                continue
            evaluator_pids.append(pid)
            assert os.readlink(root / "ns/net") != os.readlink("/proc/self/ns/net")
            assert os.readlink(root / "ns/mnt") != os.readlink("/proc/self/ns/mnt")
            assert not (root / "root/home").exists()
            values = (root / "environ").read_bytes().split(b"\0")
            assert not any(b"SECRET" in value for value in values)
            assert {value.split(b"=", 1)[0] for value in values if value} <= {
                b"GOMEMLIMIT", b"GOMAXPROCS", b"PWD"}
        assert evaluator_pids
        print(json.dumps({"batch": count, "decisions": count * 2, "unit": runner.service.unit,
                          "limits": limits, "socket_mode": "0600", "isolated_pids": evaluator_pids}))
    finally:
        runner.close()
        runner.close()
    stopped(runner)


@pytest.mark.parametrize("expression", [
    'http.send({"method":"GET","url":"http://example.invalid"})',
    'net.lookup_ip_addr("example.invalid")', 'opa.runtime()', 'time.now_ns()',
    'rand.intn("seed", 9)', 'uuid.rfc4122("seed")',
])
def test_forbidden_builtins(paths, configuration, expression):
    source, run = paths
    with (source / "rules.rego").open("a") as stream:
        stream.write(f"forbidden := {expression}\n")
    with pytest.raises(ValueError, match="could not be prepared"):
        prepare(configuration, source, run)
    assert not (run / "work/policy.tar.gz").exists()


def test_print_is_rejected(paths, configuration):
    source, run = paths
    with (source / "rules.rego").open("a") as stream:
        stream.write('forbidden if { print("must-not-leave") }\n')
    with pytest.raises(ValueError, match="could not be prepared"):
        prepare(configuration, source, run)
    assert not (run / "work/policy.tar.gz").exists()


@pytest.mark.parametrize("expression", [
    "null", "[]", '{}', '[{"id":"wrong","allow":true,"reason":"allowed"}]',
    '[{"id":"request-0","allow":"yes","reason":"allowed"}]',
    '[{"id":"request-0","allow":true,"reason":"unsafe text"}]',
])
def test_malformed_results(paths, configuration, expression):
    source, run = paths
    (source / "rules.rego").write_text(f"package ficc\ndecisions := {expression}\n")
    runner = prepare(configuration, source, run)
    with pytest.raises(ValueError, match="unavailable or invalid"):
        runner.evaluate(envelope(1))
    stopped(runner)


def test_undefined_result(paths, configuration):
    source, run = paths
    (source / "rules.rego").write_text("package ficc\nunrelated := true\n")
    runner = prepare(configuration, source, run)
    with pytest.raises(ValueError, match="unavailable or invalid"):
        runner.evaluate(envelope(1))
    stopped(runner)


def test_unavailable_service(paths, configuration):
    runner = prepare(configuration, *paths)
    process.management("kill", "--kill-whom=all", "--signal=KILL", runner.service.unit)
    with pytest.raises(ValueError, match="unavailable or invalid"):
        runner.evaluate(envelope(1))
    stopped(runner)


def test_unsafe_socket(paths, configuration):
    runner = prepare(configuration, *paths)
    runner.socket.chmod(0o666)
    with pytest.raises(ValueError, match="unavailable or invalid"):
        runner.evaluate(envelope(1))
    stopped(runner)


def test_evaluation_deadline(paths, configuration):
    source, run = paths
    (source / "rules.rego").write_text('''package ficc
decisions := [{"id": item.id, "allow": count(matches) > 0, "reason": "checked"} |
    item := input.requests[_]
    matches := [a | a := item.labels.values[_]; b := item.labels.values[_]; a == b]]
''')
    runner = prepare(configuration, source, run)
    request = envelope(1)
    request["requests"][0]["labels"]["values"] = list(range(16000))
    start = time.monotonic()
    with pytest.raises(ValueError, match="unavailable or invalid"):
        runner.evaluate(request)
    assert time.monotonic() - start < 10
    stopped(runner)


def test_response_size_limit(paths, configuration):
    source, run = paths
    (source / "rules.rego").write_text('''package ficc
decisions := [{"id": item.id, "allow": true, "reason": item.labels.text} |
    item := input.requests[_]]
''')
    runner = prepare(configuration, source, run)
    request = envelope(1)
    request["requests"][0]["labels"]["text"] = "x" * 70000
    with pytest.raises(ValueError, match="unavailable or invalid"):
        runner.evaluate(request)
    stopped(runner)


def test_controller_environment_is_not_inherited(paths, configuration, monkeypatch):
    monkeypatch.setenv("OPA_LOG_LEVEL", "debug")
    monkeypatch.setenv("GODEBUG", "invalid")
    runner = prepare(configuration, *paths)
    try:
        assert runner.evaluate(envelope(1))[0]["allow"] is True
    finally:
        runner.close()
    stopped(runner)


def test_management_loss_cleanup(paths, configuration, monkeypatch):
    runner = prepare(configuration, *paths)
    def refuse(*arguments):
        raise OSError("The service manager is unavailable.")
    monkeypatch.setattr(process, "management", refuse)
    runner.close()
    stopped(runner)


def test_cleanup_confirmation_is_required(paths, configuration, monkeypatch):
    runner = prepare(configuration, *paths)
    with monkeypatch.context() as patch:
        patch.setattr(runner.service.controls, "empty", lambda: False)
        with pytest.raises(ValueError, match="stop could not be confirmed"):
            runner.close()
        assert not runner.service.closed
    runner.close()
    stopped(runner)


def test_busy_runner_is_bounded(paths, configuration, monkeypatch):
    runner = prepare(configuration, *paths)
    monkeypatch.setattr(runner_module, "EVALUATE_SECONDS", 0.03)
    runner.lock.acquire()
    try:
        start = time.monotonic()
        with pytest.raises(ValueError, match="busy"):
            runner.evaluate(envelope(1))
        assert time.monotonic() - start < 0.5
    finally:
        runner.lock.release()
        runner.close()
    stopped(runner)


def test_compile_deadline(paths, configuration, monkeypatch):
    monkeypatch.setattr(process, "COMPILE_SECONDS", -1)
    with pytest.raises(ValueError, match="could not be prepared"):
        prepare(configuration, *paths)
    assert not (paths[1] / "work/policy.tar.gz").exists()


def test_start_deadline(paths, configuration, monkeypatch):
    monkeypatch.setattr(runner_module, "START_SECONDS", -1)
    with pytest.raises(ValueError, match="could not be prepared"):
        prepare(configuration, *paths)


def test_missing_kernel_controls(paths, configuration, monkeypatch):
    def refuse(values):
        raise ValueError("The kernel controls are unavailable.")
    monkeypatch.setattr(isolation, "enforcement", refuse)
    with pytest.raises(ValueError, match="could not be prepared"):
        prepare(configuration, *paths)
    assert not (paths[1] / "work/policy.tar.gz").exists()


def test_running_async_caller(paths, configuration):
    async def operation():
        runner = prepare(configuration, *paths)
        try:
            assert runner.evaluate(envelope(1))[0]["allow"] is True
        finally:
            runner.close()
        stopped(runner)
    asyncio.run(operation())


def test_concurrent_batches(paths, configuration):
    runner = prepare(configuration, *paths)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(runner.evaluate, (envelope(1), envelope(64))))
        assert [len(result) for result in results] == [1, 64]
    finally:
        runner.close()
    stopped(runner)


def test_controller_death(paths, configuration):
    source, run = paths
    receipt = source.parent / "child.json"
    program = '''import json,signal,sys
from pathlib import Path
from ficc_policy_opa import prepare
runner=prepare(json.loads(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
Path(sys.argv[4]).write_text(json.dumps({"unit":runner.service.unit,"group":str(runner.service.group)}))
signal.pause()
'''
    child = subprocess.Popen([sys.executable, "-c", program, json.dumps(configuration),
                              str(source), str(run), str(receipt)], stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, start_new_session=True)
    result = None
    try:
        deadline = time.monotonic() + 25
        while not receipt.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert receipt.exists(), "The real child provider did not start."
        result = json.loads(receipt.read_text())
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=3)
        deadline = time.monotonic() + 5
        while not isolation.empty(Path(result["group"])) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert isolation.empty(Path(result["group"]))
        print(json.dumps({"controller_death": True, "unit": result["unit"], "child_exit": child.returncode}))
    finally:
        process.reap(child)
        assert child.stderr is not None
        child.stderr.close()
        if result:
            process.management("stop", result["unit"])
