# SPDX-License-Identifier: Apache-2.0
"""Verify bounded epoch retirement, exact hashes and interrupted node recovery."""

import os
from pathlib import Path

import pytest
from ficc_node import file_state, history, history_files, history_scan, job_state, terminals


def request():
    return {"version": "3", "action": "history.archive", "archive_id": "a" * 32,
            "controller_id": "b" * 32, "terminal_controller": "c" * 32,
            "next_controller_id": "d" * 32, "next_terminal_controller": "e" * 32}


def node_state(tmp_path, monkeypatch, count=1):
    monkeypatch.setenv("HOME", str(tmp_path))
    body = request()
    jobs = job_state.root()
    job_state.write(jobs / "controller.json", {"id": body["controller_id"]})
    files = job_state.directory(file_state.state_root() / body["controller_id"])
    terms = terminals.base(body["terminal_controller"])
    original = {}
    for index in range(count):
        identity = f"{index:032x}"
        job = job_state.directory(jobs / identity)
        job_state.write(job / "request.json", {"controller_id": body["controller_id"], "job_id": identity,
                        "digest": f"digest-{index}", "unit": f"ficc-{body['controller_id']}-{identity}.service",
                        "description": f"FICC:{body['controller_id']}:{identity}:digest-{index}"})
        job_state.write(job / "result.json", {"state": "succeeded", "result": {"exit_code": 0}})
        for name, data in (("stdout", f"output-{index}\n".encode()), ("stderr", f"error-{index}\n".encode())):
            (job / name).write_bytes(data)
            (job / name).chmod(0o600)
        job_state.write(files / (identity + ".json"), {"id": identity, "state": "succeeded", "result": {"index": index}})
        job_state.write(terms / (identity + ".json"), {"id": identity, "state": "stopped"})
    for kind, base, lock in (("jobs", jobs, "lock"), ("files", files, "namespace.lock"), ("terminals", terms, "lock")):
        (base / lock).touch(mode=0o600)
        for path in base.rglob("*"):
            if path.is_file() and path.name not in {lock, "controller.json"}:
                original[kind + "/" + str(path.relative_to(base))] = path.read_bytes()
    monkeypatch.setattr(history_scan.job_system, "properties", lambda unit: {"LoadState": "not-found", "Id": unit})
    monkeypatch.setattr(history_scan, "no_tmux", lambda controller: None)
    return body, {"jobs": jobs, "files": files, "terminals": terms}, original


@pytest.mark.parametrize("count", [1, 64])
def test_node_archive_preserves_all_hashes_and_stable_locks(tmp_path, monkeypatch, count):
    body, bases, original = node_state(tmp_path, monkeypatch, count)
    locks = {kind: (base / ("namespace.lock" if kind == "files" else "lock")).stat().st_ino for kind, base in bases.items()}
    result = history.dispatch(body)
    assert result["state"] == "complete" and result["members"] == count * 6
    archive = Path(result["path"])
    manifest = job_state.read(archive / "manifest.json", history_files.MAX_MANIFEST)
    assert set(manifest["members"]) == set(original)
    for name, data in original.items():
        assert (archive / name).read_bytes() == data
        assert not (bases[name.split("/")[0]] / name.split("/", 1)[1]).exists()
        assert history_files.fingerprint(archive / name, history_files.maximum(name)) == manifest["members"][name]
    assert job_state.read(bases["jobs"] / "controller.json") == {"id": body["next_controller_id"]}
    for kind, base in bases.items():
        assert (base / ("namespace.lock" if kind == "files" else "lock")).stat().st_ino == locks[kind]
    assert history.dispatch(body) == result
    with pytest.raises(ValueError, match="another controller"), job_state.locked(body["controller_id"]):
        pass
    with job_state.locked(body["next_controller_id"]):
        pass
    assert sum(path.is_dir() for path in bases["jobs"].iterdir()) == 0


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("kind", ["jobs", "files", "terminals"])
def test_last_unclosed_receipt_blocks_all_retirement(tmp_path, monkeypatch, count, kind):
    body, bases, original = node_state(tmp_path, monkeypatch, count)
    identity = f"{count - 1:032x}"
    path = bases[kind] / identity / "result.json" if kind == "jobs" else bases[kind] / (identity + ".json")
    value = job_state.read(path)
    value["state"] = "unknown"
    job_state.write(path, value)
    with pytest.raises(ValueError):
        history.dispatch(body)
    assert job_state.read(bases["jobs"] / "controller.json") == {"id": body["controller_id"]}
    assert all((bases[name.split("/")[0]] / name.split("/", 1)[1]).exists() for name in original)


@pytest.mark.parametrize("unit", ["active", "mismatch", "unknown"])
@pytest.mark.parametrize("count", [1, 64])
def test_exact_unit_verification_refuses_unsafe_state(tmp_path, monkeypatch, unit, count):
    body, bases, _ = node_state(tmp_path, monkeypatch, count)
    def properties(name):
        if not name.endswith(f"-{count - 1:032x}.service"):
            return {"LoadState": "not-found", "Id": name}
        return {"LoadState": "loaded", "Id": name if unit != "mismatch" else "another.service",
                "Description": f"FICC:{body['controller_id']}:{count - 1:032x}:digest-{count - 1}",
                "ActiveState": "active" if unit == "active" else "inactive" if unit == "mismatch" else "unknown"}
    monkeypatch.setattr(history_scan.job_system, "properties", properties)
    with pytest.raises(ValueError, match="active, unknown, or has another identity"):
        history.dispatch(body)
    assert all((bases["jobs"] / f"{index:032x}").is_dir() for index in range(count))


@pytest.mark.parametrize("boundary", ["move", "manifest", "owner", "completion"])
def test_interrupted_node_archive_resumes_same_identity(tmp_path, monkeypatch, boundary):
    body, bases, original = node_state(tmp_path, monkeypatch, 3)
    calls = 0
    def failure():
        raise OSError("synthetic lost acknowledgement")
    with monkeypatch.context() as patch:
        if boundary == "move":
            actual = history_files.move
            def move(source, target):
                nonlocal calls
                actual(source, target)
                calls += 1
                if calls == 2:
                    failure()
            patch.setattr(history_files, "move", move)
        elif boundary == "owner":
            actual = history.history_write.write
            def write(path, value, maximum):
                actual(path, value, maximum)
                if path.name == "controller.json" and value == {"id": body["next_controller_id"]}:
                    failure()
            patch.setattr(history.history_write, "write", write)
        else:
            actual = history.save
            def save(path, value):
                actual(path, value)
                if (boundary == "manifest" and path.name == "manifest.json") or (boundary == "completion" and value.get("state") == "complete"):
                    failure()
            patch.setattr(history, "save", save)
        with pytest.raises(OSError, match="lost acknowledgement"):
            history.dispatch(body)
    result = history.dispatch(body)
    for name, data in original.items():
        assert (Path(result["path"]) / name).read_bytes() == data
    assert history.dispatch(body) == result
    assert job_state.read(bases["jobs"] / "controller.json") == {"id": body["next_controller_id"]}


@pytest.mark.parametrize("kind", ["wrong_owner", "symlink", "hardlink", "unexpected", "live_tmux"])
@pytest.mark.parametrize("count", [1, 64])
def test_unknown_unsafe_or_unowned_history_is_retained(tmp_path, monkeypatch, kind, count):
    body, bases, _ = node_state(tmp_path, monkeypatch, count)
    if kind == "wrong_owner":
        job_state.write(bases["jobs"] / "controller.json", {"id": "f" * 32})
    elif kind in {"symlink", "hardlink"}:
        path = bases["jobs"] / f"{count - 1:032x}" / "stdout"
        other = tmp_path / "other"
        other.write_bytes(b"preserved")
        other.chmod(0o600)
        path.unlink()
        path.symlink_to(other) if kind == "symlink" else os.link(other, path)
    elif kind == "unexpected":
        job_state.write(bases["files"] / "unexpected.json", {"state": "succeeded"})
    else:
        monkeypatch.setattr(history_scan, "no_tmux", lambda _: (_ for _ in ()).throw(ValueError("live tmux")))
    with pytest.raises((ValueError, OSError)):
        history.dispatch(body)
    assert all((bases["jobs"] / f"{index:032x}" / "result.json").exists() for index in range(count))


def test_resume_refuses_missing_unarchived_or_changed_record(tmp_path, monkeypatch):
    body, bases, _ = node_state(tmp_path, monkeypatch)
    with monkeypatch.context() as patch:
        patch.setattr(history_files, "move", lambda *args: (_ for _ in ()).throw(OSError("interrupted")))
        with pytest.raises(OSError):
            history.dispatch(body)
    (bases["files"] / ("0" * 32 + ".json")).unlink()
    with pytest.raises(ValueError, match="missing or duplicated"):
        history.dispatch(body)


def test_missing_tmux_cannot_prove_closed_namespace(monkeypatch):
    monkeypatch.setattr(history_scan.shutil, "which", lambda _: None)
    with pytest.raises(ValueError, match="tmux is required"):
        history_scan.no_tmux("a" * 32)


@pytest.mark.parametrize("boundary", ["intent", "manifest", "owner"])
def test_disk_failure_retains_same_recoverable_archive(tmp_path, monkeypatch, boundary):
    import errno

    body, bases, original = node_state(tmp_path, monkeypatch, 3)
    actual = history.history_write.write
    with monkeypatch.context() as patch:
        def write(path, value, maximum):
            if path.name == {"intent": "intent.json", "manifest": "manifest.json", "owner": "controller.json"}[boundary]:
                raise OSError(errno.ENOSPC, "synthetic disk full")
            actual(path, value, maximum)
        patch.setattr(history.history_write, "write", write)
        with pytest.raises(OSError, match="disk full"):
            history.dispatch(body)
    result = history.dispatch(body)
    assert all((Path(result["path"]) / name).read_bytes() == data for name, data in original.items())
    assert job_state.read(bases["jobs"] / "controller.json") == {"id": body["next_controller_id"]}


def test_corrupt_pending_manifest_is_refused_before_moving(tmp_path, monkeypatch):
    body, bases, _ = node_state(tmp_path, monkeypatch)
    with monkeypatch.context() as patch:
        patch.setattr(history_files, "move", lambda *args: (_ for _ in ()).throw(OSError("interrupted")))
        with pytest.raises(OSError):
            history.dispatch(body)
    path = bases["jobs"].parent / "history" / body["archive_id"] / "intent.json"
    value = job_state.read(path)
    value["members"]["../../outside"] = {"size": 1, "sha256": "a" * 64}
    job_state.write(path, value)
    with pytest.raises(ValueError, match="member path"):
        history.dispatch(body)
    assert (bases["jobs"] / ("0" * 32)).exists()


@pytest.mark.parametrize("count", [1, 64])
def test_completed_archive_rejects_changed_last_record(tmp_path, monkeypatch, count):
    body, _, _ = node_state(tmp_path, monkeypatch, count)
    result = history.dispatch(body)
    path = Path(result["path"]) / "jobs" / f"{count - 1:032x}" / "stdout"
    path.write_bytes(b"changed archived output")
    with pytest.raises(ValueError, match="hash"):
        history.dispatch(body)
