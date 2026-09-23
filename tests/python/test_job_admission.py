# SPDX-License-Identifier: Apache-2.0
"""Verify atomic node admission and conservative recovery after interrupted writes."""

import os

import pytest
from ficc_node import job_state, jobs
from test_job_node import body
from test_job_node import remote as remote


@pytest.mark.parametrize("point", ["pin", "request", "publish"])
@pytest.mark.parametrize("same_id", [False, True])
def test_prepublication_write_failure_does_not_poison_admission(remote, monkeypatch, point, same_id):
    base, starts = remote
    owner, name = (jobs, "pin_runner") if point == "pin" else (job_state, "write" if point == "request" else "publish")
    original = getattr(owner, name)

    def fail(*args, **kwargs):
        if point != "request" or args[0].name == "request.json":
            raise OSError(28, "Synthetic full disk")
        return original(*args, **kwargs)
    monkeypatch.setattr(owner, name, fail)
    with pytest.raises(OSError, match="Synthetic full disk"):
        jobs.dispatch(body())
    assert not (base / ("b" * 32)).exists()
    assert not any(entry.name.startswith(".pending-") for entry in base.iterdir())
    assert starts == []
    monkeypatch.setattr(owner, name, original)
    result = jobs.dispatch(body("b" * 32 if same_id else "c" * 32))
    assert result["state"] == "running" and len(starts) == 1


@pytest.mark.parametrize("point", ["pin", "request"])
def test_process_interruption_leaves_only_recoverable_staging(remote, monkeypatch, point):
    base, starts = remote
    owner, name = (jobs, "pin_runner") if point == "pin" else (job_state, "write")
    original = getattr(owner, name)

    def interrupted(*args, **kwargs):
        value = original(*args, **kwargs)
        if point == "pin" or args[0].name == "request.json":
            os._exit(77)
        return value
    monkeypatch.setattr(owner, name, interrupted)
    child = os.fork()
    if child == 0:
        try:
            jobs.dispatch(body())
        finally:
            os._exit(78)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 77
    stage = base / (".pending-" + "b" * 32)
    assert stage.is_dir() and not (base / ("b" * 32)).exists()
    assert (stage / "request.json").exists() == (point == "request")
    monkeypatch.setattr(owner, name, original)
    assert jobs.dispatch(body("c" * 32))["state"] == "running"
    assert not stage.exists() and len(starts) == 1


def test_published_intent_is_preserved_after_directory_sync_failure(remote, monkeypatch):
    base, starts = remote
    original = job_state.publish

    def fail_after_publish(temporary, path):
        original(temporary, path)
        raise OSError(5, "Synthetic post-publication interruption")
    monkeypatch.setattr(job_state, "publish", fail_after_publish)
    with pytest.raises(OSError, match="post-publication"):
        jobs.dispatch(body())
    path = base / ("b" * 32)
    original_request = (path / "request.json").read_bytes()
    monkeypatch.setattr(job_state, "publish", original)
    monkeypatch.setattr(jobs, "properties", lambda _: {"LoadState": "not-found"})
    assert jobs.dispatch(body())["state"] == "unknown"
    with pytest.raises(ValueError, match="unknown"):
        jobs.dispatch(body("c" * 32))
    assert (path / "request.json").read_bytes() == original_request and starts == []


def test_legacy_preintent_directory_requires_absent_unit_before_removal(remote, monkeypatch):
    base, starts = remote
    orphan = base / ("b" * 32)
    orphan.mkdir(mode=0o700)
    pinned = orphan / "runner.pyz"
    pinned.write_bytes(b"partial runner")
    pinned.chmod(0o600)
    properties = jobs.properties
    monkeypatch.setattr(jobs, "properties", lambda _: {"LoadState": "loaded"})
    with pytest.raises(ValueError, match="retained unit"):
        jobs.dispatch(body("c" * 32))
    assert pinned.read_bytes() == b"partial runner" and starts == []

    def inspect(unit):
        return {"LoadState": "not-found"} if "-" + "b" * 32 + ".service" in unit else properties(unit)
    monkeypatch.setattr(jobs, "properties", inspect)
    assert jobs.dispatch(body("c" * 32))["state"] == "running"
    assert not orphan.exists() and len(starts) == 1


@pytest.mark.parametrize("artifact", ["started.json", "stdout", "result.json", "cancel.json"])
def test_missing_intent_with_execution_artifacts_is_never_deleted(remote, monkeypatch, artifact):
    base, starts = remote
    orphan = base / ("b" * 32)
    orphan.mkdir(mode=0o700)
    file = orphan / artifact
    file.write_bytes(b"evidence")
    file.chmod(0o600)
    monkeypatch.setattr(jobs, "properties", lambda _: {"LoadState": "not-found"})
    with pytest.raises(ValueError, match="explicit recovery"):
        jobs.dispatch(body("c" * 32))
    assert file.read_bytes() == b"evidence" and starts == []
