# SPDX-License-Identifier: Apache-2.0
"""Detect abrupt process loss, unsafe scratch recovery and missing directory persistence."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from ficc_node import history, history_files, history_write, job_state
from test_history_node import node_state, request


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("kind,boundary", [("node", name) for name in ("intent", "manifest", "published", "owner", "complete")]
                         + [("controller", name) for name in ("initial", "bound", "ack", "retirement", "complete", "cli-published")])
def test_abrupt_exit_before_every_journal_replacement_resumes(tmp_path, kind, boundary, count):
    command = [sys.executable, str(Path(__file__).with_name("history_crash_child.py")), kind, boundary, str(count), str(tmp_path)]
    crash = subprocess.run(command[:2] + ["crash"] + command[2:], capture_output=True, timeout=90)
    assert crash.returncode == 77, crash.stderr.decode()
    assert list(tmp_path.rglob(".archive-write-*.tmp")), "The abrupt exit must leave an actual unpublished scratch file."
    marker = json.loads((tmp_path / "crash.json").read_bytes())
    if boundary in {"intent", "initial", "manifest", "retirement"}:
        # These writes must also recover when their authoritative target has never existed.
        assert not any(path.name == marker["target"] for path in tmp_path.rglob(marker["target"]))
    results = []
    for _ in range(2):
        resumed = subprocess.run(command[:2] + ["resume"] + command[2:], capture_output=True, timeout=90)
        assert resumed.returncode == 0, resumed.stderr.decode()
        results.append(json.loads(resumed.stdout))
    assert results[0] == results[1]
    if kind == "node":
        assert results[0]["archive_id"] == request()["archive_id"]
    elif boundary != "initial":
        pending_value = marker["value"].get("intent", marker["value"])
        if "archive_id" in pending_value:
            assert results[0]["archive_id"] == pending_value["archive_id"]


@pytest.mark.parametrize("count", [1, 64])
def test_abrupt_cli_creation_resumes_with_all_sanitized_receipts(tmp_path, count):
    command = [sys.executable, str(Path(__file__).with_name("history_crash_child.py")), "controller", "cli-created", str(count), str(tmp_path)]
    crash = subprocess.run(command[:2] + ["crash"] + command[2:], capture_output=True, timeout=90)
    assert crash.returncode == 77, crash.stderr.decode()
    expected = json.loads((tmp_path / "crash.json").read_bytes())
    copies = [path for path in (tmp_path / "archive/cli").iterdir() if expected["target"] in path.name]
    assert len(copies) == 1 and copies[0].stat().st_size == 0
    results = []
    for _ in range(2):
        resumed = subprocess.run(command[:2] + ["resume"] + command[2:], capture_output=True, timeout=90)
        assert resumed.returncode == 0, resumed.stderr.decode()
        results.append(json.loads(resumed.stdout))
    assert results[0] == results[1]


@pytest.mark.parametrize("count", [0, 1, 64])
def test_all_parent_entries_persist_before_move_and_owner_commit(tmp_path, monkeypatch, count):
    if count:
        body, _, _ = node_state(tmp_path, monkeypatch, count)
    else:
        monkeypatch.setenv("HOME", str(tmp_path))
        body = request()
        monkeypatch.setattr(history.history_scan, "no_tmux", lambda _: None)
        assert not (tmp_path / ".local").exists()
    archive = tmp_path / ".local/state/ficc/history" / body["archive_id"]
    required = {str(path) for path in (archive, *archive.parents) if path == tmp_path or path.is_relative_to(tmp_path)}
    seen = set()
    actual_sync, actual_rename, actual_write = os.fsync, history_files.rename, history_write.write
    def sync(fd):
        seen.add(os.readlink(f"/proc/self/fd/{fd}"))
        return actual_sync(fd)
    def rename(source_fd, source, target_fd, target):
        target_parent = Path(os.readlink(f"/proc/self/fd/{target_fd}"))
        assert required | {str(target_parent)} <= seen, "The archive parent chain must persist before moving its first record."
        return actual_rename(source_fd, source, target_fd, target)
    def write(path, value, maximum):
        if path.name == "controller.json":
            assert required <= seen, "The new namespace owner must not precede archive ancestry persistence."
        return actual_write(path, value, maximum)
    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(history_files, "rename", rename)
    monkeypatch.setattr(history_write, "write", write)
    result = history.dispatch(body)
    assert result["state"] == "complete" and result["members"] == count * 6
    assert required <= seen


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "oversize", "fifo", "directory"])
def test_unsafe_reserved_scratch_is_not_deleted(tmp_path, kind):
    target = tmp_path / "intent.json"
    scratch = tmp_path / history_write.temporary(target.name)
    other = tmp_path / "unrelated"
    other.write_bytes(b"unrelated data")
    other.chmod(0o600)
    if kind == "symlink":
        scratch.symlink_to(other)
    elif kind == "hardlink":
        os.link(other, scratch)
    elif kind == "fifo":
        os.mkfifo(scratch, 0o600)
    elif kind == "directory":
        scratch.mkdir(mode=0o700)
    else:
        scratch.write_bytes(b"x" * (65 if kind == "oversize" else 1))
        scratch.chmod(0o644 if kind == "public" else 0o600)
    with pytest.raises((ValueError, OSError)):
        history_write.recover(target, 64)
    assert scratch.exists() or scratch.is_symlink()
    assert other.read_bytes() == b"unrelated data"


def test_partial_reserved_scratch_recovers_without_discarding_unexpected_files(tmp_path):
    target = tmp_path / "intent.json"
    scratch = tmp_path / history_write.temporary(target.name)
    scratch.write_bytes(b'{"incomplete":')
    scratch.chmod(0o600)
    unexpected = tmp_path / ".write-unrelated"
    unexpected.write_bytes(b"preserve")
    history_write.write(target, {"complete": True}, 64)
    assert job_state.read(target) == {"complete": True}
    assert not scratch.exists() and unexpected.read_bytes() == b"preserve"
