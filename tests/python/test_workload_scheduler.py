# SPDX-License-Identifier: Apache-2.0
"""Consume the installed scheduler and verify fair ordering and strict quota admission."""

import json
from types import SimpleNamespace

import pytest

from ficc.workloads import provider
from ficc.workloads.cli import configure


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_installed_scheduler_rotates_projects_and_counts_unresolved_capacity(tmp_path, count):
    from ficc_scheduler_fair import create
    scheduler = create({"global_active": count, "project_active": 1})
    jobs = [{"id": f"{project:032x}:{generation}", "project_id": f"{project:032x}", "created_at": float(generation)}
            for project in range(1, count + 2) for generation in range(2)]
    first = scheduler.select({"version": 1, "pending": jobs, "active": []})
    assert len(first) == count and len({identity.split(":")[0] for identity in first}) == count
    active = [{"id": str(index), "job_id": identity, "project_id": identity.split(":")[0]} for index, identity in enumerate(first)]
    assert scheduler.select({"version": 1, "pending": jobs, "active": active}) == []
    next_round = scheduler.select({"version": 1, "pending": jobs, "active": []})
    assert next_round[0].split(":")[0] == f"{count + 1:032x}"


def test_configuration_uses_real_entry_point_and_preserves_previous_file_on_failure(tmp_path):
    state = tmp_path / "state"
    source = tmp_path / "configuration.json"
    source.write_text(json.dumps({"provider": "fair", "configuration": {"global_active": 16, "project_active": 4}}))
    source.chmod(0o600)
    assert provider.load(state) is None
    assert configure(state, source)["configured"]
    previous = (state / "workload-provider.json").read_bytes()
    source.write_text(json.dumps({"provider": "fair", "configuration": {"global_active": 2, "project_active": 4}}))
    with pytest.raises(ValueError, match="cannot exceed"):
        configure(state, source)
    assert (state / "workload-provider.json").read_bytes() == previous
    assert provider.load(state).global_active == 16


def test_provider_cannot_propose_duplicates_or_nonpending_jobs():
    job = SimpleNamespace(id="a" * 32, project_id="b" * 32, created_at=1.0, state="queued", cancelled=False)
    for values in ([job.id, job.id], ["c" * 32], [None]):
        with pytest.raises(ValueError, match="invalid or duplicate"):
            provider.select(SimpleNamespace(select=lambda _request: values), [job], [])
