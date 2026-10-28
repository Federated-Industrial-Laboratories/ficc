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


@pytest.mark.parametrize("change", [None, "outside", "other_device", "missing_connection", "other_connection"])
def test_userspace_overlay_requires_exact_kernel_connection_and_reserved_directory_fds(tmp_path, monkeypatch, change):
    from pathlib import Path
    from types import SimpleNamespace

    from ficc.execution import layered
    root = tmp_path / "attempt/runtime/storage"
    root.mkdir(parents=True)
    proc = tmp_path / "proc/42"
    (proc / "fd").mkdir(parents=True)
    (proc / "fdinfo").mkdir()
    for index, name in enumerate(("lower", "upper", "work")):
        target = root / name
        target.mkdir()
        (proc / "fd" / str(index)).symlink_to(target)
    (proc / "fd/3").symlink_to("/dev/null")
    connection = "" if change == "missing_connection" else "fuse_connection: " + ("101" if change == "other_connection" else "100")
    (proc / "fdinfo/3").write_text(connection)
    original = Path.stat
    def observed(path, **kwargs):
        if path == proc / "fd/3":
            return SimpleNamespace(st_mode=0o20666, st_rdev=os.makedev(10, 229))
        return original(path, **kwargs)
    monkeypatch.setattr(Path, "stat", observed)
    device = root.stat().st_dev
    ctx = {"directory": str(tmp_path / "attempt"), "binding": {"device": device}}
    if change == "outside":
        (proc / "fd/0").unlink()
        (proc / "fd/0").symlink_to(tmp_path)
    if change == "other_device":
        ctx["binding"]["device"] += 1
    if change:
        with pytest.raises(ValueError, match="reserved filesystem|FUSE connection"):
            layered.backing(ctx, {"device": "0:100"}, proc)
    else:
        assert len(layered.backing(ctx, {"device": "0:100"}, proc)) == 3


def test_managed_overlay_cannot_silently_fall_back_to_native_fd_layers(tmp_path):
    from ficc.execution.gate import filesystem
    main = {"target": "/", "fstype": "overlay", "options": ["ro"],
            "super_options": "lowerdir=3:6:7,upperdir=/unbound,workdir=/unbound"}
    with pytest.raises(ValueError, match="ignored its approved"):
        filesystem({"directory": str(tmp_path)}, {"overlay_helper": {"inode": 1}}, 42, [main], [])
    with pytest.raises(ValueError, match="outside the reserved filesystem"):
        filesystem({"directory": str(tmp_path)}, {}, 42, [main], [])


@pytest.mark.parametrize("change", [None, "cgroup", "executable", "owner"])
def test_userspace_overlay_requires_approved_executable_and_task_cgroup(tmp_path, monkeypatch, change):
    from pathlib import Path

    from ficc.execution import layered
    from ficc.execution.files import identity
    proc = tmp_path / "proc/42"
    proc.mkdir(parents=True)
    approved = Path("/usr/bin/true")
    if change == "owner":
        approved = tmp_path / "untrusted-helper"
        approved.write_bytes(b"untrusted")
    (proc / "exe").symlink_to("/usr/bin/false" if change == "executable" else approved)
    (proc / "stat").write_text("42 (helper) " + " ".join(["0"] * 20))
    (proc / "cgroup").write_text("0::/other/manager" if change == "cgroup" else "0::/task/manager")
    (proc / "status").write_text("Uid:\t" + " ".join([str(os.getuid())] * 4) + "\nGid:\t" + " ".join([str(os.getgid())] * 4))
    def path(value):
        return {"/proc": tmp_path / "proc", "/usr/bin/fuse-overlayfs": approved}.get(str(value), Path(value))
    monkeypatch.setattr(layered, "Path", path)
    monkeypatch.setattr(layered, "processes", lambda uid: [42])
    monkeypatch.setattr(layered, "backing", lambda *args: [{"verified_directory": True}])
    ctx = {"slot": {"uid": os.getuid(), "gid": os.getgid()}, "cgroup": "/task"}
    prepared = {"overlay_helper": identity(approved.stat())}
    if change:
        with pytest.raises(ValueError, match="helper"):
            layered.verify(ctx, prepared, {"device": "0:100"})
    else:
        assert layered.verify(ctx, prepared, {"device": "0:100"})["pid"] == 42


@pytest.mark.parametrize("result", ["refused", "different_targets", "changed_root"])
def test_disposable_metadata_inspection_refuses_incomplete_or_changed_proof_and_closes_fds(monkeypatch, result):
    from pathlib import Path
    from types import SimpleNamespace

    from ficc.execution import mount_probe
    descriptors = []
    namespace_before = Path("/proc/self/ns/user").stat().st_ino
    credentials_before = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    def invoke(argv, **options):
        assert argv[1:5] == ["-I", "-B", "-m", "ficc.execution.mount_probe"]
        assert options["timeout"] == 5 and options["pass_fds"] == tuple(map(int, argv[-2:]))
        descriptors.extend(options["pass_fds"])
        assert all(os.fstat(fd) for fd in descriptors)
        data = {"targets": {} if result == "different_targets" else {"/proof": {}}, "shared_memory_bytes": 0}
        return SimpleNamespace(returncode=1 if result == "refused" else 0, stdout=json.dumps(data).encode())
    monkeypatch.setattr(mount_probe.subprocess, "run", invoke)
    if result == "changed_root":
        sequence = iter([("1", "1"), ("2", "2")])
        monkeypatch.setattr(mount_probe, "root_identity", lambda fd: next(sequence))
    with pytest.raises(ValueError, match="inspection|different targets"):
        mount_probe.inspect(os.getpid(), ["/proof"], False)
    assert credentials_before == (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    assert Path("/proc/self/ns/user").stat().st_ino == namespace_before
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
