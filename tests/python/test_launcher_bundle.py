# SPDX-License-Identifier: Apache-2.0
"""Keep verified AppImage payloads private, immutable and independent of the mount."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from ficc.launcher_bundle import install


def payload(tmp_path, monkeypatch, count=1):
    source = tmp_path / "mounted payload"
    source.mkdir()
    files = {}
    for index in range(count):
        name = "python/bin/ficc" if index == 0 else f"module-{index}.py"
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = f"distinct payload {index}\n".encode()
        path.write_bytes(data)
        path.chmod(0o755)
        files[name] = hashlib.sha256(data).hexdigest()
    (source / "command-link").symlink_to("python/bin/ficc")
    (source / "bundle.json").write_text(json.dumps({"files": files, "links": {"command-link": "python/bin/ficc"}}))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private data"))
    return source


@pytest.mark.parametrize("count", [1, 64])
def test_install_retains_all_bytes_after_mount_removal(tmp_path, monkeypatch, count):
    source = payload(tmp_path, monkeypatch, count)
    command = install(source)
    assert command.read_bytes() == (source / "python/bin/ficc").read_bytes()
    assert install(source) == command
    root = command.parents[2]
    assert root.stat().st_mode & 0o777 == 0o700
    assert len(list(root.rglob("*.py"))) == count - 1
    for index in range(count):
        name = "python/bin/ficc" if index == 0 else f"module-{index}.py"
        assert (root / name).read_bytes() == f"distinct payload {index}\n".encode()
    source.rename(source.with_name("unmounted"))
    assert command.read_bytes() == b"distinct payload 0\n"
    assert (root / "command-link").resolve() == command


@pytest.mark.parametrize("change", ["extra", "changed", "missing", "external-link"])
def test_install_rejects_changed_source(tmp_path, monkeypatch, change):
    source = payload(tmp_path, monkeypatch)
    if change == "extra":
        (source / "extra.py").write_text("extra code")
    elif change == "changed":
        (source / "python/bin/ficc").write_text("changed code")
    elif change == "missing":
        (source / "python/bin/ficc").unlink()
    else:
        (source / "command-link").unlink()
        (source / "command-link").symlink_to("../../outside")
    with pytest.raises(ValueError):
        install(source)


@pytest.mark.parametrize("count", [1, 64])
def test_existing_runtime_is_not_silently_replaced(tmp_path, monkeypatch, count):
    source = payload(tmp_path, monkeypatch, count)
    command = install(source)
    changed = command if count == 1 else command.parents[2] / f"module-{count - 1}.py"
    changed.write_text("changed installed code")
    with pytest.raises(ValueError, match="changed"):
        install(source)
    assert changed.read_text() == "changed installed code"


@pytest.mark.parametrize("count", [1, 64])
def test_install_rejects_changed_last_source_member(tmp_path, monkeypatch, count):
    source = payload(tmp_path, monkeypatch, count)
    name = "python/bin/ficc" if count == 1 else f"module-{count - 1}.py"
    (source / name).write_text("unverified last member")
    with pytest.raises(ValueError, match="changed"):
        install(source)
    assert not list((tmp_path / "private data/ficc/runtimes").glob("*/python/bin/ficc"))


def test_concurrent_installers_share_one_complete_runtime(tmp_path, monkeypatch):
    source = payload(tmp_path, monkeypatch, 64)
    with ThreadPoolExecutor(max_workers=4) as workers:
        commands = list(workers.map(lambda _: install(source), range(4)))
    assert len(set(commands)) == 1
    assert commands[0].is_file()
