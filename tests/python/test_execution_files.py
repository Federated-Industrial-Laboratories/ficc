# SPDX-License-Identifier: Apache-2.0
"""Keep executor file permissions exact under a private service creation mask."""

import os
import stat

import pytest

from ficc.execution.files import atomic, identity, read_json
from ficc.execution.monitor import marker


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_atomic_request_cdi_and_private_state_modes_survive_service_umask(tmp_path, count):
    mask = os.umask(0o077)
    try:
        for index in range(count):
            root = tmp_path / f"attempt-{index}"
            root.mkdir()
            for name, mode in (("request.json", 0o440), ("gpu.json", 0o440), ("state.json", 0o600)):
                path = root / name
                path.write_text("previous")
                previous = path.stat()
                value = {"attempt_id": f"{index:032x}", "file": name, "value": index * 7 + 3}
                atomic(path, value, mode)
                current = path.stat()
                assert read_json(path) == value
                assert stat.S_IMODE(current.st_mode) == mode
                assert not current.st_mode & 0o022
                assert (current.st_uid, current.st_gid) == (previous.st_uid, previous.st_gid)
                assert current.st_nlink == 1
            assert sorted(path.name for path in root.iterdir()) == ["gpu.json", "request.json", "state.json"]
    finally:
        os.umask(mask)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_launch_and_release_markers_keep_read_access_without_shared_write(tmp_path, count):
    mask = os.umask(0o077)
    try:
        for index in range(count):
            root = tmp_path / f"attempt-{index}"
            root.mkdir()
            for name in ("launch", "release"):
                path = root / name
                marker(path)
                before = path.stat()
                assert path.read_bytes() == b"release\n"
                assert stat.S_IMODE(before.st_mode) == 0o444
                assert not before.st_mode & 0o222
                assert (before.st_uid, before.st_gid) == (root.stat().st_uid, root.stat().st_gid)
                assert before.st_nlink == 1
                marker(path)
                assert identity(path.stat()) == identity(before)
    finally:
        os.umask(mask)


def test_atomic_mode_failure_keeps_previous_receipt_and_removes_temporary_file(tmp_path, monkeypatch):
    path = tmp_path / "request.json"
    original = {"state": "previous"}
    atomic(path, original)
    before = path.stat()

    def denied(_fd, _mode):
        raise PermissionError("The requested file mode is unavailable.")

    monkeypatch.setattr(os, "fchmod", denied)
    with pytest.raises(PermissionError, match="file mode"):
        atomic(path, {"state": "replacement"}, 0o440)
    assert read_json(path) == original
    assert identity(path.stat()) == identity(before)
    assert list(tmp_path.iterdir()) == [path]


def test_marker_is_complete_and_readable_before_publication(tmp_path, monkeypatch):
    path = tmp_path / "release"
    replace = os.replace
    observed = []

    def publish(source, destination):
        assert destination == path and not path.exists()
        assert source.read_bytes() == b"release\n"
        assert stat.S_IMODE(source.stat().st_mode) == 0o444
        observed.append(source)
        replace(source, destination)

    monkeypatch.setattr(os, "replace", publish)
    mask = os.umask(0o077)
    try:
        marker(path)
    finally:
        os.umask(mask)
    assert len(observed) == 1 and list(tmp_path.iterdir()) == [path]
