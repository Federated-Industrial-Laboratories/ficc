# SPDX-License-Identifier: Apache-2.0
"""Retire revoked node bookkeeping without inventing cleanup or permitting replay."""

import pytest
from project_module_fixtures import console
from test_execution_ledger import offer
from workload_fixtures import INSTALLATION, contributor, placement, result, submitted

from ficc.errors import Failure
from ficc.workloads.records import validate_records


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_revoked_unknown_attempts_require_acknowledgement_and_never_claim_cleanup(storage_state, monkeypatch, count):
    with console(storage_state, monkeypatch) as (client, service):
        actor = service.auth.resolve(client.cookies.get("ficc_session"))
        queue = service.workloads
        node = contributor(service, actor.project_id)
        jobs = []
        for index in range(count):
            job = submitted(service, actor, node, index)
            plan, lease = placement(job, node["id"])
            queue.records.reserve(plan, lease, INSTALLATION, offer(count).limits)
            queue.records.observation(result(plan, "unknown", False), node["id"], INSTALLATION)
            job = queue.records.get(job.id)
            with pytest.raises(Failure, match="Acknowledge"):
                queue.abandon(job.id, job.revision, actor, False)
            with pytest.raises(Failure, match="Revoke"):
                queue.abandon(job.id, job.revision, actor, True)
            jobs.append((job, plan))
        with pytest.raises(ValueError, match="active or unknown"):
            validate_records(service.store.db)
        service.contributors.records.disable(node["id"], node["revision"], actor)
        for job, plan in jobs:
            value = queue.abandon(job.id, job.revision, actor, True)
            attempt = queue.records.attempt(plan.attempt_id)
            assert value["state"] == "unknown" and value["attempt"]["state"] == "abandoned"
            assert attempt.outcome.state == "unknown" and attempt.outcome.cleanup_confirmed is False
            assert attempt.observed.cleanup_confirmed is False
            with pytest.raises(Failure, match="confirmed storage release"):
                queue.records.retry(job.id, value["revision"], job.delegation, acknowledge_unknown=True)
            with pytest.raises(Failure, match="retired"):
                queue.records.observation(result(plan), node["id"], INSTALLATION)
            with pytest.raises(Failure, match="disabled"):
                queue.authority.capture(actor, job.request)
        validate_records(service.store.db)
        assert len([event for event in service.store.events() if event["action"] == "workload.abandon"]) == count
