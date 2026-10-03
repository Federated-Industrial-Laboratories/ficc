# SPDX-License-Identifier: Apache-2.0
"""Reject a real unconfined child and retain its inspected kernel evidence."""

import json
import os
import subprocess
import sys

import pytest

from ficc.execution.gate import core_limit, inspect


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_live_unconfined_process_is_never_released_and_inspection_precedes_assertions(tmp_path, count):
    for index in range(count):
        directory = tmp_path / str(index)
        directory.mkdir()
        child = subprocess.Popen([sys.executable, "-I", "-c", "import time; print('ready', flush=True); time.sleep(15)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            assert child.stdout.readline() == b"ready\n"
            ctx = {"directory": str(directory), "slot": {"uid": os.getuid(), "gid": os.getgid()},
                   "cgroup": "/ficc-qualified-private-attempt"}
            with pytest.raises(ValueError):
                inspect(ctx, {}, child.pid)
            evidence = json.loads((directory / "inspection.json").read_text())
            assert evidence["pid"] == child.pid and evidence["status"] and evidence["mountinfo"]
            assert evidence["start_time"].isdigit()
            assert not (directory / "control/release").exists()
        finally:
            child.terminate()
            child.communicate(timeout=5)


@pytest.mark.parametrize("limit", [0, 1048576])
def test_actual_child_core_limits_must_be_zero_for_both_soft_and_hard_values(limit):
    child = subprocess.run([sys.executable, "-I", "-c",
        "import pathlib,resource,sys; n=int(sys.argv[1]); resource.setrlimit(resource.RLIMIT_CORE,(0,n)); "
        "print(pathlib.Path('/proc/self/limits').read_text())", str(limit)], check=True, capture_output=True, text=True)
    if limit == 0:
        core_limit(child.stdout)
    else:
        with pytest.raises(ValueError, match="core dump"):
            core_limit(child.stdout)
