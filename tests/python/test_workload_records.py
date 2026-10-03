# SPDX-License-Identifier: Apache-2.0
"""Preserve reservations and uncertain outcomes across actual state-store restarts."""

import secrets

import pytest
from project_module_fixtures import console
from test_execution_ledger import offer
from workload_fixtures import INSTALLATION, contributor, placement, result, submitted

from ficc.errors import Failure
from ficc.workloads.records import Records, validate_records


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distinct_attempts_recover_without_replay_and_hold_capacity(storage_state, monkeypatch, count):
    with console(storage_state, monkeypatch) as (client, service):
        actor = service.auth.resolve(client.cookies.get("ficc_session"))
        node = contributor(service, actor.project_id)
        records = Records(service.store)
        pairs = []
        for index in range(count):
            job = submitted(service, actor, node, index)
            assert records.submit(job.request, job.key, job.delegation).id == job.id
            plan, lease = placement(job, node["id"])
            attempt = records.reserve(plan, lease, INSTALLATION, offer(count).limits)
            records.observation(result(plan, "unknown", False), node["id"], INSTALLATION)
            revision = records.get(job.id).revision
            records.observation(result(plan, "unknown", False), node["id"], INSTALLATION)
            assert records.get(job.id).revision == revision
            pairs.append((job, plan, lease, attempt))
        extra = submitted(service, actor, node, 0)
        with pytest.raises(Failure, match="reserved"):
            records.reserve(*placement(extra, node["id"]), INSTALLATION, offer(count).limits)
        with pytest.raises(ValueError, match="active or unknown"):
            validate_records(service.store.db)
        before = [item.model_dump() for item in records.attempts()]
    with console(storage_state, monkeypatch) as (_client, service):
        records = Records(service.store)
        assert [item.model_dump() for item in records.attempts()] == before
        for job, plan, lease, _attempt in pairs:
            current = records.get(job.id)
            with pytest.raises(Failure, match="confirmed storage release"):
                records.retry(job.id, current.revision, job.delegation)
            with pytest.raises(Failure, match="changed"):
                records.reserve(plan, lease, INSTALLATION, offer(count).limits)
            assert records.attempt(plan.attempt_id).state == "unknown"
            records.observation(result(plan), node["id"], INSTALLATION)
            finished = records.get(job.id)
            with pytest.raises(Failure, match="confirmed storage release"):
                records.retry(job.id, finished.revision, job.delegation)
            records.observation(result(plan, "released"), node["id"], INSTALLATION)
            assert records.attempt(plan.attempt_id).outcome == result(plan)
            assert records.get(job.id).state == "succeeded"
            audit = service.store.db.execute("SELECT action,outcome,actor,subject_id,project_id FROM audit "
                                            "WHERE target=:p0 ORDER BY id", (plan.attempt_id,)).fetchall()
            assert [tuple(row) for row in audit] == [
                (action, outcome, job.actor, job.subject_id, job.project_id) for action, outcome in (
                    ("workload.admit", "preparing"), ("workload.observe", "unknown"),
                    ("workload.observe", "succeeded"), ("workload.cleanup", "confirmed"), ("workload.observe", "released"))]
        for job, plan, _lease, _attempt in pairs:
            current = records.get(job.id)
            records.retry(job.id, current.revision, job.delegation)
            successor, lease = placement(records.get(job.id), node["id"])
            assert successor.generation == 2
            records.reserve(successor, lease, INSTALLATION, offer(count).limits)
            with pytest.raises(Failure, match="released attempt"):
                records.observation(result(plan), node["id"], INSTALLATION)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_failed_admission_rolls_back_job_and_reservation_together(storage_state, monkeypatch, count):
    with console(storage_state, monkeypatch) as (client, service):
        actor = service.auth.resolve(client.cookies.get("ficc_session"))
        node = contributor(service, actor.project_id)
        records = Records(service.store)
        for index in range(count):
            job = submitted(service, actor, node, index)
            plan, lease = placement(job, node["id"])
            def unavailable(*_args):
                raise OSError("Synthetic state write failure")
            for boundary in ("save_job", "audit"):
                with monkeypatch.context() as patch:
                    patch.setattr(records, boundary, unavailable)
                    with pytest.raises(OSError, match="write failure"):
                        records.reserve(plan, lease, INSTALLATION, offer(count).limits)
                assert records.get(job.id).state == "queued"
                assert records.get(job.id).current_attempt is None
                assert plan.attempt_id not in {item.id for item in records.attempts()}
                assert not service.store.db.execute("SELECT 1 FROM audit WHERE target=:p0", (plan.attempt_id,)).fetchone()
            records.reserve(plan, lease, INSTALLATION, offer(count).limits)
        assert len(records.attempts()) == count


def test_fences_and_final_results_cannot_be_substituted(storage_state, monkeypatch):
    with console(storage_state, monkeypatch) as (client, service):
        actor = service.auth.resolve(client.cookies.get("ficc_session"))
        node = contributor(service, actor.project_id)
        records = Records(service.store)
        job = submitted(service, actor, node)
        plan, lease = placement(job, node["id"])
        records.reserve(plan, lease, INSTALLATION, offer(1).limits)
        for field, value in (("generation", 2), ("plan_digest", "sha256:" + "0" * 64)):
            changed = result(plan).model_copy(update={field: value})
            with pytest.raises(Failure, match="does not bind"):
                records.observation(changed, node["id"], INSTALLATION)
        with pytest.raises(Failure, match="does not bind"):
            records.observation(result(plan), node["id"], secrets.token_hex(16))
        records.observation(result(plan), node["id"], INSTALLATION)
        with pytest.raises(Failure, match="cannot change"):
            records.observation(result(plan).model_copy(update={"output_bytes": 99}), node["id"], INSTALLATION)
        with pytest.raises(Failure, match="active state"):
            records.observation(result(plan, "running"), node["id"], INSTALLATION)
