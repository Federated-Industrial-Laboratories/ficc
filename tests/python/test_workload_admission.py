# SPDX-License-Identifier: Apache-2.0
"""Reconcile missing admission replies without repeating execution or replacing ledger identity."""

import json
import secrets

import pytest
from project_module_fixtures import console
from workload_fixtures import INSTALLATION, contributor, placement, submitted
from workload_queue_fixtures import SyntheticExecutor

from ficc.errors import Failure
from ficc.execution.wire import Attempt as LocalAttempt
from ficc.execution.wire import Snapshot
from ficc.workloads.schema import Attempt


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_missing_prepare_receipts_reconcile_after_restart_without_start_or_replay(storage_state, monkeypatch, count):
    ledger_id = secrets.token_hex(16)
    identities = []
    with console(storage_state, monkeypatch) as (client, service):
        actor = service.auth.resolve(client.cookies.get("ficc_session"))
        node = contributor(service, actor.project_id)
        fake = SyntheticExecutor(service.workloads, node, count)
        for index in range(count):
            job = submitted(service, actor, node, index)
            plan, lease = placement(job, node["id"])
            service.workloads.records.reserve(plan, lease, INSTALLATION, fake.offer.limits,
                                              ledger_id=ledger_id, admission_version=1)
            service.workloads.records.transition(plan.attempt_id, "preparing", "unknown", "executor_reply_unknown")
            identities.append((job.id, plan.attempt_id, plan.digest()))
    with console(storage_state, monkeypatch) as (client, service):
        actor = service.auth.resolve(client.cookies.get("ficc_session"))
        queue = service.workloads
        fake = SyntheticExecutor(queue, node, count)
        fake.installation, fake.ledger_id = INSTALLATION, ledger_id
        monkeypatch.setattr(service.contributors.records, "authenticate", fake.authenticate)
        monkeypatch.setattr(queue.channel, "request", fake.request)
        await queue.runner.node(node["id"])
        assert node["id"] not in queue.runner.errors
        assert len(fake.attempts) == count and not fake.starts
        for index, (job_id, attempt_id, binding) in enumerate(identities):
            if index % 8 == 0:
                fake.pulse()
                await queue.runner.node(node["id"])
            job, attempt = queue.records.get(job_id), queue.records.attempt(attempt_id)
            assert job.state == "failed" and job.reason == "admission_rejected" and job.generation == 1
            assert (attempt.ledger_id, attempt.admission_version) == (ledger_id, 1)
            assert attempt.outcome.plan_digest == binding and attempt.outcome.cleanup_confirmed
            assert attempt.start_requested is False
            with pytest.raises(Failure, match="confirmed storage release"):
                await queue.retry(job.id, job.revision, actor)
            released = await queue.release(job.id, job.revision, actor)
            assert released["attempt"]["state"] == "released" and released["state"] == "failed"
        await queue.runner.node(node["id"])
        assert len(queue.records.attempts()) == count and not fake.starts
        assert all(queue.records.attempt(identity).state == "released" for _, identity, _ in identities)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("boundary", ["legacy", "started", "replaced"])
async def test_absence_never_resolves_legacy_started_or_other_ledger_work(storage_state, monkeypatch, count, boundary):
    with console(storage_state, monkeypatch) as (client, service):
        actor = service.auth.resolve(client.cookies.get("ficc_session"))
        node = contributor(service, actor.project_id)
        queue = service.workloads
        fake = SyntheticExecutor(queue, node, count)
        monkeypatch.setattr(queue.channel, "request", fake.request)
        attempts = []
        for index in range(count):
            job = submitted(service, actor, node, index)
            plan, lease = placement(job, node["id"])
            ledger_id = None if boundary == "legacy" else secrets.token_hex(16) if boundary == "replaced" else fake.ledger_id
            attempt = queue.records.reserve(plan, lease, fake.installation, fake.offer.limits,
                                            ledger_id=ledger_id, admission_version=0 if ledger_id is None else 1)
            attempt.start_requested = boundary == "started"
            with service.store.lock, service.store.db:
                queue.records.save_attempt(attempt)
            attempts.append(queue.records.transition(attempt.id, "preparing", "unknown", "executor_reply_unknown"))
        await queue.runner.reject_absent(node["id"], Snapshot.model_validate(fake.snapshot()), attempts)
        assert not fake.attempts and not fake.starts
        for attempt in queue.records.attempts():
            assert attempt.state == "unknown" and attempt.observed is None and attempt.outcome is None


def test_retained_ledger_identity_blocks_replacement_and_result_substitution(storage_state, monkeypatch):
    with console(storage_state, monkeypatch) as (client, service):
        actor = service.auth.resolve(client.cookies.get("ficc_session"))
        node = contributor(service, actor.project_id)
        queue = service.workloads
        fake = SyntheticExecutor(queue, node, 1)
        snapshot = Snapshot.model_validate(fake.snapshot())
        queue.nodes.save(snapshot)
        job = submitted(service, actor, node)
        plan, lease = placement(job, node["id"])
        attempt = queue.records.reserve(plan, lease, fake.installation, fake.offer.limits,
                                        ledger_id=fake.ledger_id, admission_version=1)
        other = snapshot.model_copy(update={"ledger_id": secrets.token_hex(16)})
        with pytest.raises(Failure, match="replacement executor ledger"):
            queue.nodes.save(other)
        local = LocalAttempt(attempt_id=attempt.id, generation=plan.generation, plan_digest=plan.digest(),
            state="failed", reason="admission_rejected", exit_code=None, output_bytes=0, error_bytes=0,
            cleanup_confirmed=True, job_id=job.id, project_id=job.project_id, offer_revision=plan.offer_revision,
            lease_sequence=0, lease_expires_at=0, ready=False, outcome="failed")
        with pytest.raises(Failure, match="another executor admission ledger"):
            queue.commands.observation(local, other)
        assert queue.records.attempt(attempt.id).observed is None
        legacy = attempt.model_dump(exclude={"ledger_id", "admission_version"})
        assert Attempt.model_validate_json(json.dumps(legacy)).ledger_id is None
        with pytest.raises(ValueError, match="admission contract"):
            Attempt.model_validate({**legacy, "admission_version": 1})
        old_snapshot = snapshot.model_dump(exclude={"ledger_id", "admission_version"})
        parsed = Snapshot.model_validate(old_snapshot)
        assert parsed.admission_version == 0 and parsed.ledger_id is None
