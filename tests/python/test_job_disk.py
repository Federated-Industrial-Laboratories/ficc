# SPDX-License-Identifier: Apache-2.0
"""Verify archived output still counts against physical storage admission."""

from types import SimpleNamespace

import pytest
from ficc_node import jobs
from test_job_node import body
from test_job_node import remote as remote


def test_full_node_refuses_new_intent_but_retains_existing_status(remote, monkeypatch):
    base, starts = remote
    first = jobs.dispatch(body())
    assert first["state"] == "running" and len(starts) == 1
    monkeypatch.setattr(jobs.os, "statvfs", lambda _: SimpleNamespace(f_bavail=0, f_frsize=4096))
    assert jobs.dispatch(body())["state"] == "running"
    assert len(starts) == 1
    from ficc_node import job_state
    job_state.write(base / ("b" * 32) / "result.json", {"state": "succeeded", "result": {"exit_code": 0}})
    with pytest.raises(ValueError, match="free storage"):
        jobs.dispatch(body("c" * 32))
    assert not (base / ("c" * 32)).exists() and len(starts) == 1
    assert not list(base.glob(".pending-*"))
    monkeypatch.setattr(jobs.os, "statvfs", lambda _: SimpleNamespace(f_bavail=1024*1024, f_frsize=4096))
    assert jobs.dispatch(body("c" * 32))["state"] == "running"
    assert len(starts) == 2
