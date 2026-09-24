# SPDX-License-Identifier: Apache-2.0
"""Verify cancellation intent across queued work, failures, and restart."""

import asyncio
import copy

import pytest
from test_jobs import manual_poll as manual_poll
from test_jobs import prepare, request, submit

from ficc.errors import Failure
from ficc.jobs import Jobs


@pytest.mark.parametrize("count", [1, 64])
def test_cancelled_waiting_workers_never_contact_nodes(console, monkeypatch, count):
    client, service, remote, actor = prepare(console, monkeypatch, count)
    operation, _ = submit(client, request(count))

    async def scenario():
        jobs = service.jobs
        for _ in range(4):
            await jobs.workers.acquire()
        pending = [asyncio.create_task(jobs.work(operation["id"], target["node_id"], target["job_id"]))
                   for target in operation["targets"]]
        await asyncio.sleep(0)
        assert not any(task.done() for task in pending)
        await jobs.cancel(operation["id"], request(count)["node_ids"], False, actor)
        before = copy.deepcopy(jobs.store.get(operation["id"])["targets"])
        for _ in range(4):
            jobs.workers.release()
        await asyncio.gather(*pending)
        after = jobs.store.get(operation["id"])["targets"]
        assert after == before
        assert all(target["state"] == "cancelled" and target["result"]["reason"] == "cancelled_before_dispatch"
                   for target in after)
        assert [body["action"] for _, body in remote.calls if body["action"] != "job.capabilities"] == []
        assert not any(jobs.store.active(node_id) for node_id in request(count)["node_ids"])
    asyncio.run(scenario())


def test_cancel_retries_after_transport_failure_and_restart(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    attempts = []

    async def lossy(node, body, check=None):
        if body["action"] == "job.cancel":
            check()
            attempts.append(copy.deepcopy(body))
            if len(attempts) == 1:
                raise Failure("unreachable", "Connection did not reach the machine.", 502)
        return await remote.job(node, body, check)
    monkeypatch.setattr(service.ssh, "job", lossy)
    asyncio.run(service.jobs.cancel(operation["id"], ["node-0"], False, actor))
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    first = service.jobs.store.get(operation["id"])["targets"][0]
    assert first["state"] == "cancel_requested" and first["cancel_status"] == "pending"
    assert "Cancellation pending" in first["error"] and "Connection" in first["error"]
    service.jobs = Jobs(service)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    last = service.jobs.store.get(operation["id"])["targets"][0]
    assert last["state"] == "cancelled" and last["cancel_status"] == "complete"
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    assert not service.jobs.store.active("node-0")


def test_cancel_revocation_stays_visible_after_restart_and_status(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    _, grant = service.auth.issue("token", scopes=["jobs:cancel"], node_ids=["node-0"])
    asyncio.run(service.jobs.cancel(operation["id"], ["node-0"], False, grant.id))
    service.auth.revoke(grant.id)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    target = service.jobs.store.get(operation["id"])["targets"][0]
    assert target["cancel_status"] == "denied" and "Cancellation denied" in target["error"]
    denied = target["error"]
    service.jobs = Jobs(service)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    target = service.jobs.store.get(operation["id"])["targets"][0]
    assert target["state"] == "running" and target["error"] == denied
    assert not any(body["action"] == "job.cancel" for _, body in remote.calls)
    public = client.get("/api/v1/operations/" + operation["id"]).json()["targets"][0]
    assert not any(key.startswith("cancel_") for key in public)
    asyncio.run(service.jobs.cancel(operation["id"], ["node-0"], True, actor))
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "cancelled"
    assert [body["force"] for _, body in remote.calls if body["action"] == "job.cancel"] == [True]


@pytest.mark.parametrize("failure", [False, True])
def test_force_escalation_survives_older_inflight_reply(console, monkeypatch, failure):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))

    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()
        attempts = []

        async def delayed(node, body, check=None):
            if body["action"] == "job.cancel":
                check()
                attempts.append(copy.deepcopy(body))
                if len(attempts) == 1:
                    started.set()
                    await release.wait()
                    if failure:
                        raise Failure("unreachable", "Older request lost its acknowledgement.", 502)
                    return {"job_id": body["job_id"], "state": "running", "result": None, "error": None}
            return await remote.job(node, body, check)
        monkeypatch.setattr(service.ssh, "job", delayed)
        await service.jobs.cancel(operation["id"], ["node-0"], False, actor)
        older = asyncio.create_task(service.jobs.reconcile(operation["id"], "node-0"))
        await started.wait()
        await service.jobs.cancel(operation["id"], ["node-0"], True, actor)
        latest = service.jobs.store.get(operation["id"])["targets"][0]
        release.set()
        await older
        stored = service.jobs.store.get(operation["id"])["targets"][0]
        assert stored["cancel_revision"] == latest["cancel_revision"] and stored["cancel_force"]
        assert stored["state"] == "cancel_requested" and stored["cancel_status"] == "pending"
        await service.jobs.reconcile(operation["id"], "node-0")
        assert [body["force"] for body in attempts] == [False, True]
        assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "cancelled"
    asyncio.run(scenario())


@pytest.mark.parametrize("expiry", [False, True])
def test_retry_rechecks_revoked_or_expired_cancellation_grant(console, monkeypatch, expiry):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    _, grant = service.auth.issue("token", scopes=["jobs:cancel"], node_ids=["node-0"])
    attempts = []

    async def disconnected(node, body, check=None):
        if body["action"] == "job.cancel":
            check()
            attempts.append(copy.deepcopy(body))
            raise Failure("unreachable", "No cancellation connection.", 502)
        return await remote.job(node, body, check)
    monkeypatch.setattr(service.ssh, "job", disconnected)
    asyncio.run(service.jobs.cancel(operation["id"], ["node-0"], False, grant.id))
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    if expiry:
        with service.store.db:
            service.store.db.execute("UPDATE credentials SET expires=0 WHERE id=?", (grant.id,))
    else:
        service.auth.revoke(grant.id)
    service.jobs = Jobs(service)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    target = service.jobs.store.get(operation["id"])["targets"][0]
    assert len(attempts) == 1
    assert target["cancel_status"] == "denied" and "Cancellation denied" in target["error"]
    assert target["state"] == "running"


def test_force_escalation_before_ssh_dispatch_supersedes_old_request(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))

    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()
        preparation = 0
        dispatched = []

        async def slow_configuration(node, body, check=None):
            nonlocal preparation
            preparation += 1
            if preparation == 1:
                started.set()
                await release.wait()
            check()
            dispatched.append(copy.deepcopy(body))
            return await remote.job(node, body, check)
        monkeypatch.setattr(service.ssh, "job", slow_configuration)
        await service.jobs.cancel(operation["id"], ["node-0"], False, actor)
        older = asyncio.create_task(service.jobs.reconcile(operation["id"], "node-0"))
        await started.wait()
        await service.jobs.cancel(operation["id"], ["node-0"], True, actor)
        release.set()
        await older
        assert dispatched == []
        await service.jobs.reconcile(operation["id"], "node-0")
        assert [body["force"] for body in dispatched] == [True]
        assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "cancelled"
    asyncio.run(scenario())
