# SPDX-License-Identifier: Apache-2.0
"""Detect surviving descendants, pipe closure, and missing cancellation grace."""

import io
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from ficc_node.job_process import capture


def payload(source):
    return subprocess.Popen([sys.executable, "-c", source], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)


def collect(proc, interrupted=lambda: False):
    return capture(proc, {"stdout": io.BytesIO(), "stderr": io.BytesIO()}, 4096, 3, interrupted)


def test_closed_pipes_do_not_end_a_running_payload(tmp_path):
    done = tmp_path / "done"
    proc = payload(f"import os,time,pathlib;os.close(1);os.close(2);time.sleep(0.25);pathlib.Path({str(done)!r}).write_text('done')")
    before = time.monotonic()
    code, reason, _, _ = collect(proc)
    assert code == 0 and reason == "exit"
    assert done.read_text() == "done" and time.monotonic() - before >= 0.2


def test_descendant_is_stopped_before_parent_reap(tmp_path):
    pidfile = tmp_path / "pid"
    child = f"import os,time,pathlib;pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()));os.close(1);os.close(2);time.sleep(10)"
    parent = f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child!r}]);time.sleep(0.15)"
    proc = payload(parent)
    collect(proc)
    pid = int(pidfile.read_text())
    stat = Path(f"/proc/{pid}/stat")
    for _ in range(20):
        if not stat.exists() or stat.read_text().split()[2] == "Z":
            break
        time.sleep(0.05)
    else:
        os.kill(pid, signal.SIGKILL)
        raise AssertionError("A descendant survived managed group cleanup.")


def test_normal_cancel_allows_term_handler_to_finish(tmp_path):
    ready, done = tmp_path / "ready", tmp_path / "done"
    source = f"""import signal,time,pathlib

def stop(signum, frame):
    time.sleep(0.25)
    pathlib.Path({str(done)!r}).write_text('grace')
    raise SystemExit(0)

signal.signal(signal.SIGTERM,stop)
pathlib.Path({str(ready)!r}).write_text('ready')
time.sleep(10)
"""
    proc = payload(source)
    deadline = time.monotonic() + 2
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists()
    before = time.monotonic()
    code, reason, _, _ = collect(proc, lambda: True)
    assert code == 0 and reason == "signal"
    assert done.read_text() == "grace" and time.monotonic() - before >= 0.2


def test_new_process_group_with_open_pipe_is_cleaned_before_eof(tmp_path):
    pidfile = tmp_path / "escaped-pid"
    child = f"import os,time,pathlib;pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()));time.sleep(10)"
    parent = f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child!r}],start_new_session=True);time.sleep(0.15)"
    proc = payload(parent)
    settled = []

    def cleanup():
        settled.append(True)
        pid = int(pidfile.read_text())
        fd = os.pidfd_open(pid)
        try:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        finally:
            os.close(fd)
        return True

    started = time.monotonic()
    try:
        code, reason, _, _ = capture(proc, {"stdout": io.BytesIO(), "stderr": io.BytesIO()},
                                     4096, 3, lambda: False, cleanup)
        assert code == 0 and reason == "exit" and settled == [True]
        assert time.monotonic() - started < 2
    finally:
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
