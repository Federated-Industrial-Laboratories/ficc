# SPDX-License-Identifier: Apache-2.0
"""Exercise project queue submission, dispatch, output retention, and uncertain recovery."""

import base64
import secrets
from types import SimpleNamespace

import pytest
from policy_fixtures import activate, install_pack
from project_module_fixtures import checked
from test_execution_ledger import plan as sample_plan
from test_identity_projects import member
from workload_fixtures import contributor
from workload_queue_fixtures import SyntheticExecutor, scheduler

from ficc.errors import Failure
from ficc.execution.ledger import Ledger
from ficc.execution.spec import encoded
from ficc.execution.supervisor import public
from ficc.execution.wire import Snapshot
from ficc.workloads.commands import Commands
from ficc.workloads.routes import OutputRead
from ficc.workloads.runner import Runner
from ficc.workloads.schema import Submission


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_project_workloads_complete_with_explicit_output_release_and_no_start_replay(policy_console, monkeypatch, count):
    client, service, material = policy_console
    scopes = ["jobs:read", "jobs:execute", "jobs:cancel", "jobs:logs", "contributors:read"]
    user, project, actor, headers = member(service, "Workload operator", scopes=scopes)
    outside, other_project, _other, attack = member(service, "Outside workload operator", scopes=scopes)
    for subject, space in ((user, project), (outside, other_project)):
        checked(client.put(f"/api/v1/projects/{space['id']}/policy-roles/{subject['id']}", json={"roles": ["operator"], "revision": 0}))
    activate(client, install_pack(client, material))
    node = contributor(service, project["id"])
    queue = service.workloads
    scheduler(queue)
    fake = SyntheticExecutor(queue, node, count)
    monkeypatch.setattr(service.contributors.records, "authenticate", fake.authenticate)
    monkeypatch.setattr(queue.channel, "request", fake.request)
    items = [{"key": secrets.token_hex(16), "request": {"job": sample_plan(index).job.model_dump(), "node_ids": [node["id"]]}}
             for index in range(count)]
    submitted = checked(client.post("/api/v1/workloads", headers=headers, json={"requests": items}), 202)["results"]
    assert len(submitted) == count and all(item["ok"] for item in submitted)
    identities = [item["workload"]["id"] for item in submitted]
    assert len(set(identities)) == count
    assert client.get("/api/v1/workloads", headers=attack).json()["workloads"] == []
    assert client.get(f"/api/v1/workloads/{identities[-1]}", headers=attack).status_code == 404
    service.auth.revoke(actor.id)
    _token, resumed = service.auth.issue("token", "Resumed workload reader", scopes=scopes,
        subject_id=user["id"], project_id=project["id"])
    for index, identity in enumerate(identities):
        fake.pulse()
        fake.finish = False
        await queue.runner.node(node["id"])
        await queue.runner.schedule()
        assert queue.records.get(identity).state == "prepared"
        fake.drop_start = index == count - 1
        await queue.runner.node(node["id"])
        assert queue.records.get(identity).state == ("unknown" if index == count - 1 else "running")
        if index == count - 1:
            # Recreate the dispatcher from retained records before asking the same executor for its truth.
            queue.runner, queue.commands = Runner(queue), Commands(queue)
            await queue.runner.node(node["id"])
            assert queue.records.get(identity).state == "running"
        fake.finish = True
        await queue.runner.node(node["id"])
        job = queue.records.get(identity)
        expected = ("succeeded", "failed", "cancelled", "unknown")[index % 4]
        assert job.state == expected
        output = await queue.collect(identity, [OutputRead(object="stdout", offset=0, length=4096)], resumed)
        assert base64.b64decode(output["results"][0]["data"]) == fake.output(job.current_attempt)
        with pytest.raises(Failure, match="confirmed storage release"):
            await queue.retry(identity, job.revision, resumed)
        before = job.current_attempt
        released = await queue.release(identity, job.revision, resumed)
        assert released["attempt"]["state"] == "released" and released["state"] == expected
        assert fake.starts[before] == 1
        with pytest.raises(Failure, match="released"):
            await queue.collect(identity, [OutputRead(object="stdout", offset=0, length=4096)], resumed)
    assert len(fake.starts) == count and all(value == 1 for value in fake.starts.values())
    last = queue.records.get(identities[-1])
    if last.state == "unknown":
        with pytest.raises(Failure, match="confirmed storage release"):
            await queue.retry(last.id, last.revision, resumed)
        retry = await queue.retry(last.id, last.revision, resumed, acknowledge_unknown=True)
        assert retry["state"] == "queued" and retry["generation"] == 1


async def test_refused_oldest_job_does_not_block_eligible_work_or_overbook_one_local_slot(policy_console, monkeypatch):
    client, service, material = policy_console
    activate(client, install_pack(client, material))
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    node = contributor(service, actor.project_id)
    queue = service.workloads
    scheduler(queue, 3)
    fake = SyntheticExecutor(queue, node, 3)
    monkeypatch.setattr(service.contributors.records, "authenticate", fake.authenticate)
    monkeypatch.setattr(queue.channel, "request", fake.request)
    jobs = []
    for index in range(3):
        job = sample_plan(index).job
        if index == 0:
            job.runtime.image_digest = "sha256:" + "0" * 64
        jobs.append(await queue.submit(Submission(job=job, node_ids=[node["id"]]), secrets.token_hex(16), actor))
    await queue.runner.node(node["id"])
    await queue.runner.schedule()
    assert queue.records.get(jobs[0]["id"]).reason == "local_runtime_refused"
    assert queue.records.get(jobs[1]["id"]).state == "prepared"
    assert queue.records.get(jobs[2]["id"]).reason == "executor_busy"
    assert len(fake.attempts) == 1 and len(queue.records.attempts()) == 1


async def test_reconciliation_streams_lifetime_history_without_discarding_fences(tmp_path):
    from test_execution_ledger import INSTALLATION, offer

    tmp_path.chmod(0o700)
    ledger = Ledger(tmp_path, INSTALLATION)
    try:
        with ledger.db:
            for index in range(8257):
                plan = sample_plan(index)
                row = {"plan": plan.model_dump(), "plan_digest": plan.digest(), "slot": None,
                       "state": "released", "outcome": "succeeded", "reason": None, "exit_code": 0,
                       "output_bytes": 0, "error_bytes": 0, "cleanup_confirmed": True,
                       "lease_sequence": 1, "lease_expires_at": 1}
                ledger.db.execute("INSERT INTO attempts VALUES (?,?,?,?,?,?,?)",
                    (plan.attempt_id, plan.job_id, 1, plan.digest(), "released", None, encoded(row).decode()))
        ledger.close()
        ledger = Ledger(tmp_path, INSTALLATION)
        pages = 0

        async def snapshot(_identity, after=None):
            nonlocal pages
            pages += 1
            rows, more = ledger.page(after)
            return Snapshot(installation_id=INSTALLATION, ledger_id=ledger.identity, admission_version=1,
                deployment_id=plan.deployment_id, node_id=plan.node_id, maximum_lease_seconds=30, offer=offer(1),
                capacity={"slots": [], "providers": [], "available": offer(1).limits.model_dump()},
                attempts=[public(row) for row in rows], next=rows[-1]["plan"]["attempt_id"] if more else None)

        def absent(_identity):
            raise Failure("not_found", "The controller record was removed.", 404)

        queue = SimpleNamespace(channel=SimpleNamespace(session=lambda _identity: {"id": "session"}),
            records=SimpleNamespace(attempt=absent, attempts=lambda _identity: []),
            commands=SimpleNamespace(snapshot=snapshot))
        runner = Runner(queue)
        await runner.reconcile(plan.node_id, await snapshot(plan.node_id))
        assert pages == 130 and plan.node_id in runner.reconciled
        assert ledger.db.execute("SELECT count(*) FROM attempts").fetchone()[0] == 8257
        assert ledger.retained() == []
    finally:
        ledger.close()
