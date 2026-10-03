# SPDX-License-Identifier: Apache-2.0
"""Check current kernel object identity and every bounded process member."""

import os
from pathlib import Path

import pytest

from ficc_policy_opa import isolation


class Kernel:
    def __init__(self, root: Path, count: int, offset: int):
        self.group = root / "groups" / f"policy-{offset}"
        self.group.mkdir(parents=True)
        self.processes = root / "processes"
        self.processes.mkdir(exist_ok=True)
        self.pids = list(range(offset, offset + count))
        self.membership = f"0::/policy-{offset}"
        contents = {"memory.max": str(isolation.MEMORY_BYTES), "memory.swap.max": "0",
                    "pids.max": "64", "cpu.max": "100000 100000", "cgroup.type": "domain",
                    "cgroup.stat": "nr_descendants 0\nnr_dying_descendants 0\n",
                    "cgroup.procs": "\n".join(map(str, self.pids)),
                    "cgroup.events": "populated 1\nfrozen 0\n", "cgroup.kill": ""}
        for name, value in contents.items():
            (self.group / name).write_text(value)
        for pid in self.pids:
            process = self.processes / str(pid)
            (process / "task" / str(pid)).mkdir(parents=True)
            (process / "status").write_text(f"Pid:\t{pid}\nState:\tS (sleeping)\nNoNewPrivs:\t1\n")
            (process / "cgroup").write_text("1:net_cls:/\n" + self.membership + "\n")
            (process / "task" / str(pid) / "children").write_text("")
        (self.processes / str(offset) / "task" / str(offset) / "children").write_text(
            " ".join(map(str, self.pids[1:])))

    def controls(self):
        return isolation.Controls(self.group, str(self.pids[0]))


@pytest.fixture
def kernel(tmp_path, monkeypatch):
    monkeypatch.setattr(isolation, "CGROUP_ROOT", tmp_path / "groups")
    monkeypatch.setattr(isolation, "PROC_ROOT", tmp_path / "processes")
    return lambda count, offset=10000: Kernel(tmp_path, count, offset)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("defect", ["privileges", "membership", "dead", "missing", "escaped_child"])
def test_current_member_failure_is_local(kernel, count, defect):
    target, healthy = kernel(count), kernel(1, 20000)
    controls, control = target.controls(), healthy.controls()
    try:
        controls.check()
        control.check()
        last = target.processes / str(target.pids[-1])
        if defect == "privileges":
            path = last / "status"
            original = path.read_text()
            path.write_text(original.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"))
        elif defect == "membership":
            path = last / "cgroup"
            original = path.read_text()
            path.write_text("0::/another-policy\n")
        elif defect == "dead":
            path = last / "status"
            original = path.read_text()
            path.write_text(original.replace("S (sleeping)", "Z (zombie)"))
        elif defect == "missing":
            path = last / "status"
            original = path.read_text()
            path.unlink()
        else:
            path = last / "task" / str(target.pids[-1]) / "children"
            original = path.read_text()
            path.write_text("90000")
        with pytest.raises(ValueError, match="current kernel"):
            controls.check()
        control.check()
        path.write_text(original)
        controls.check()
        assert len(set(target.pids)) == count
    finally:
        descriptors = [controls.main, controls.directory, control.main, control.directory]
        controls.close()
        control.close()
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("name,value", [
    ("memory.max", "max"), ("memory.swap.max", "1"), ("pids.max", "63"),
    ("cpu.max", "200000 100000"), ("cgroup.type", "threaded"),
    ("cgroup.stat", "nr_descendants 1"), ("cgroup.procs", ""),
    ("cgroup.procs", "20000"), ("cgroup.procs", "1\n" * 65),
])
def test_current_limits_and_group_shape(kernel, name, value):
    target = kernel(1)
    controls = target.controls()
    try:
        (target.group / name).write_text(value)
        with pytest.raises(ValueError, match="current kernel"):
            controls.check()
    finally:
        controls.close()


def test_replaced_group_is_not_admitted_or_killed(kernel):
    target = kernel(1)
    controls = target.controls()
    original = target.group.with_name("retained")
    target.group.rename(original)
    target.group.mkdir()
    (target.group / "cgroup.kill").write_text("unchanged")
    try:
        with pytest.raises(ValueError, match="current kernel"):
            controls.check()
        controls.kill()
        assert (original / "cgroup.kill").read_text() == "1"
        assert (target.group / "cgroup.kill").read_text() == "unchanged"
        assert not controls.empty()
        (original / "cgroup.events").write_text("populated 0\n")
        assert controls.empty()
    finally:
        controls.close()


def test_main_process_descriptor_cannot_follow_replacement(kernel):
    target = kernel(1)
    controls = target.controls()
    original = target.processes / str(target.pids[0])
    moved = original.with_name("previous")
    original.rename(moved)
    original.mkdir()
    (original / "status").write_text("Pid:\t10000\nState:\tS (sleeping)\nNoNewPrivs:\t1\n")
    (moved / "status").write_text("Pid:\t10000\nState:\tZ (zombie)\nNoNewPrivs:\t1\n")
    try:
        with pytest.raises(ValueError, match="current kernel"):
            controls.check()
    finally:
        controls.close()


@pytest.mark.parametrize("defect", ["oversized", "symlink", "fifo", "missing"])
def test_kernel_file_bounds(kernel, defect):
    target = kernel(1)
    controls = target.controls()
    path = target.processes / str(target.pids[0]) / "status"
    path.unlink()
    if defect == "oversized":
        path.write_text("x" * 16385)
    elif defect == "symlink":
        path.symlink_to(target.group / "cgroup.stat")
    elif defect == "fifo":
        os.mkfifo(path)
    try:
        with pytest.raises(ValueError, match="current kernel"):
            controls.check()
    finally:
        controls.close()


def test_failed_admission_closes_descriptors(kernel):
    target = kernel(1)
    (target.processes / str(target.pids[0]) / "status").unlink()
    before = set(Path("/proc/self/fd").iterdir())
    with pytest.raises(ValueError, match="current kernel"):
        target.controls()
    assert set(Path("/proc/self/fd").iterdir()) == before


def test_missing_events_need_deleted_group(kernel):
    target = kernel(1)
    controls = target.controls()
    (target.group / "cgroup.events").unlink()
    try:
        with pytest.raises(FileNotFoundError):
            controls.empty()
        for path in target.group.iterdir():
            path.unlink()
        target.group.rmdir()
        assert controls.empty()
    finally:
        controls.close()
