# SPDX-License-Identifier: Apache-2.0
"""Observe owned child exit without waitid or reaping before group cleanup."""

import os
import signal
import subprocess
import sys
import time

import pytest
from ficc_node import agent_process


@pytest.fixture(autouse=True)
def without_waitid(monkeypatch):
    # Python 3.12 on macOS does not export this optional Unix interface.
    monkeypatch.delattr(os, "waitid", raising=False)


def test_version_exit_status_and_reap_follow_group_cleanup(monkeypatch):
    popen = subprocess.Popen
    kill = agent_process.kill_group
    children = []
    signals = []

    def spawn(*args, **kwargs):
        child = popen(*args, **kwargs)
        if args[0][0] == sys.executable:
            children.append(child)
        return child

    def checked_kill(pid, sig=signal.SIGKILL):
        assert children[-1].returncode is None
        signals.append(sig)
        return kill(pid, sig)

    monkeypatch.setattr(agent_process.subprocess, "Popen", spawn)
    monkeypatch.setattr(agent_process, "kill_group", checked_kill)
    assert agent_process.version([sys.executable]) == "Python " + sys.version.split()[0]
    assert children[-1].returncode == 0
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    with pytest.raises(ValueError, match="check failed"):
        agent_process.version([sys.executable, "-c", "raise SystemExit(7)"])
    assert children[-1].returncode == 7
    with pytest.raises(ValueError, match="check failed"):
        agent_process.version([sys.executable, "-c", "import os,signal; os.kill(os.getpid(),signal.SIGTERM)"])
    assert children[-1].returncode == -signal.SIGTERM


def test_finished_leader_is_still_waitable_until_group_stop():
    process = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while agent_process.alive(process):
            assert time.monotonic() < deadline
            time.sleep(.01)
        assert process.returncode is None
        # A PID lookup still finds the zombie: observation has not reaped it.
        os.kill(process.pid, 0)
        agent_process.stop_group(process)
        assert process.returncode == 0
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        agent_process.stop_group(process)
    finally:
        if process.returncode is None:
            agent_process.stop_group(process)


def test_stop_kills_term_resistant_group_before_wait(monkeypatch):
    process = subprocess.Popen([sys.executable, "-c",
        "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
        "print('ready',flush=True); time.sleep(30)"], stdout=subprocess.PIPE,
        start_new_session=True)
    try:
        assert process.stdout.readline() == b"ready\n"
        assert agent_process.alive(process)
        real_wait = process.wait
        real_kill = agent_process.kill_group
        signals = []

        def kill(pid, sig=signal.SIGKILL):
            assert process.returncode is None
            signals.append(sig)
            real_kill(pid, sig)

        def wait(*args, **kwargs):
            assert signals == [signal.SIGTERM, signal.SIGKILL]
            return real_wait(*args, **kwargs)

        monkeypatch.setattr(agent_process, "kill_group", kill)
        monkeypatch.setattr(process, "wait", wait)
        started = time.monotonic()
        agent_process.stop_group(process)
        assert time.monotonic() - started < 6
        assert process.returncode == -signal.SIGKILL
    finally:
        if process.returncode is None:
            agent_process.stop_group(process)
        process.stdout.close()


def test_readiness_failure_still_kills_and_reaps_owned_child(monkeypatch):
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                               start_new_session=True)

    def unavailable(pid):
        raise OSError("Exit readiness unavailable")

    monkeypatch.setattr(agent_process, "process_descriptor", unavailable)
    with pytest.raises(OSError, match="readiness unavailable"):
        agent_process.stop_group(process)
    assert process.returncode is not None


def test_version_kills_descendant_after_leader_has_exited(tmp_path):
    child_file = tmp_path / "child"
    script = (
        "import os,pathlib,signal,time\n"
        f"path=pathlib.Path({str(child_file)!r})\n"
        "if os.fork()==0:\n"
        " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
        " os.close(1); os.close(2)\n"
        " path.write_text(str(os.getpid()))\n"
        " time.sleep(5); os._exit(0)\n"
        "while not path.exists(): time.sleep(.01)\n"
        "print('fixture-version',flush=True); os._exit(0)\n"
    )
    assert agent_process.version([sys.executable, "-c", script]) == "fixture-version"
    child = child_file.read_text()
    deadline = time.monotonic() + 1
    while True:
        status = subprocess.run(["/bin/ps", "-p", child, "-o", "stat="],
                                capture_output=True, text=True, timeout=2, check=False)
        if status.returncode == 1 or status.stdout.strip().startswith("Z"):
            break
        assert status.returncode == 0, status.stderr
        assert time.monotonic() < deadline, "The descendant survived group cleanup."
        time.sleep(.01)


@pytest.mark.parametrize("script, error", [
    ("import time; time.sleep(30)", "timed out"),
    ("import os,time; os.close(1); time.sleep(30)", "did not exit"),
    ("print('x'*4097)", "exceeds capacity"),
])
def test_version_failure_paths_are_bounded_and_reaped(monkeypatch, script, error):
    popen = subprocess.Popen
    children = []

    def spawn(*args, **kwargs):
        child = popen(*args, **kwargs)
        if args[0][0] == sys.executable:
            children.append(child)
        return child

    monkeypatch.setattr(agent_process.subprocess, "Popen", spawn)
    started = time.monotonic()
    with pytest.raises(ValueError, match=error):
        agent_process.version([sys.executable, "-c", script])
    assert time.monotonic() - started < 8
    assert children[0].returncode is not None
