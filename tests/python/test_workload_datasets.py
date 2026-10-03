# SPDX-License-Identifier: Apache-2.0
"""Protect immutable dataset bindings and resumable contributor input delivery."""

import asyncio
import base64
import hashlib
import secrets
import time
from types import SimpleNamespace

import pytest
from policy_fixtures import activate, install_pack
from test_datasets import registered
from test_execution_ledger import plan as sample_plan
from workload_fixtures import contributor
from workload_queue_fixtures import SyntheticExecutor, scheduler

from ficc.errors import Failure
from ficc.execution.wire import REPLY
from ficc.workloads import records as records_module
from ficc.workloads import runner as runner_module
from ficc.workloads.schema import Submission


async def dataset_workload(policy_console, tmp_path):
    client, service, material = policy_console
    activate(client, install_pack(client, material))
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    node = contributor(service, actor.project_id)
    scheduler(service.workloads)
    path = tmp_path / "dataset"
    path.mkdir()
    data = bytes(range(256)) * 8200
    source = path / "values.csv"
    source.write_bytes(data)
    root = await service.files.register(str(path), "Dataset input")
    dataset, _ = await registered(service, actor.id, root)
    original = Submission(job=sample_plan(0).job, node_ids=[node["id"]])
    assert "dataset" not in original.model_dump()
    request = Submission(**original.model_dump(), dataset={"id": dataset["id"], "manifest_digest": dataset["manifest_digest"]})
    return service, actor, node, source, data, request


async def test_dataset_delivery_resumes_from_receipt_after_lost_write_acknowledgement(policy_console, tmp_path, monkeypatch):
    service, actor, node, _source, data, request = await dataset_workload(policy_console, tmp_path)
    queue = service.workloads
    fake = SyntheticExecutor(queue, node, 1)
    monkeypatch.setattr(service.contributors.records, "authenticate", fake.authenticate)
    accepted = bytearray()
    writes = []

    async def exchange(identity, message, check, **kwargs):
        fake.pulse()
        if message.action in {"input_status", "input_write"}:
            check()
            asked = (message.objects if message.action == "input_status" else message.writes)[0]
            item = fake.plans[asked.attempt_id].job.inputs[0]
            if message.action == "input_write":
                assert asked.offset == len(accepted)
                accepted.extend(base64.b64decode(asked.data))
                writes.append(asked.offset)
                if len(writes) == 1:
                    raise Failure("executor_reply_unknown", "The write acknowledgement was lost.", 504)
            return REPLY.validate_python({"version": 1, "id": message.id, "deployment_id": "b" * 32,
                "node_id": identity, "ok": True, "results": [{**asked.model_dump(include={"attempt_id", "generation", "plan_digest"}),
                    "ok": True, "object": item.id, "offset": len(accepted), "bytes": item.bytes,
                    "digest": item.digest, "complete": len(accepted) == item.bytes}]})
        reply = await fake.request(identity, message, check, **kwargs)
        if message.action == "observe":
            for row in reply.results:
                row.attempt.ready = len(accepted) == len(data)
                fake.attempts[row.attempt_id]["ready"] = row.attempt.ready
        return reply

    monkeypatch.setattr(queue.channel, "request", exchange)
    key = secrets.token_hex(16)
    job = await queue.submit(request, key, actor)
    assert (await queue.submit(request, key, actor))["id"] == job["id"]
    selected = queue.records.get(job["id"]).request.job.inputs[0]
    assert selected.delivery == "stream" and selected.digest == "sha256:" + hashlib.sha256(data).hexdigest()
    await queue.runner.node(node["id"])
    await queue.runner.schedule()
    for _ in range(10):
        fake.pulse()
        await queue.runner.node(node["id"])
        await asyncio.gather(*(work.task for work in queue.inputs.pending.values()), return_exceptions=True)
        if queue.records.get(job["id"]).state == "running":
            break
    saved = queue.records.get(job["id"])
    assert saved.state == "running" and fake.starts[saved.current_attempt] == 1, (saved.state, queue.runner.errors, writes)
    assert bytes(accepted) == data and writes == [0, 1048576, 2097152]


async def test_dataset_source_change_cancels_staging_and_cannot_be_rebound(policy_console, tmp_path, monkeypatch):
    service, actor, node, source, _data, request = await dataset_workload(policy_console, tmp_path)
    queue = service.workloads
    fake = SyntheticExecutor(queue, node, 1)
    monkeypatch.setattr(service.contributors.records, "authenticate", fake.authenticate)
    monkeypatch.setattr(queue.channel, "request", fake.request)
    changed = request.model_copy(update={"dataset": request.dataset.model_copy(update={"manifest_digest": "0" * 64})})
    with pytest.raises(Failure, match="manifest differs"):
        await queue.submit(changed, secrets.token_hex(16), actor)
    job = await queue.submit(request, secrets.token_hex(16), actor)
    await queue.runner.node(node["id"])
    await queue.runner.schedule()
    source.write_bytes(b"changed source")

    async def status(identity, action, fields, check):
        assert action == "input_status"
        asked = fields["objects"][0]
        item = queue.records.get(job["id"]).request.job.inputs[0]
        return REPLY.validate_python({"version": 1, "id": secrets.token_hex(16), "deployment_id": "b" * 32,
            "node_id": identity, "ok": True, "results": [{**asked, "ok": True, "offset": 0,
                "bytes": item.bytes, "digest": item.digest, "complete": False}]})

    monkeypatch.setattr(queue.commands, "call", status)
    assert not await queue.inputs.advance(node["id"], queue.records.attempts(node["id"]))
    failures = await asyncio.gather(*(work.task for work in queue.inputs.pending.values()), return_exceptions=True)
    assert any(isinstance(value, Failure) and value.code == "stale_entry" for value in failures)
    assert not await queue.inputs.advance(node["id"], queue.records.attempts(node["id"]))
    assert queue.records.get(job["id"]).cancelled
    assert not fake.starts


async def test_delayed_source_allows_lease_renewal_and_owns_cancelled_read(policy_console, tmp_path, monkeypatch):
    service, actor, node, _source, _data, request = await dataset_workload(policy_console, tmp_path)
    queue = service.workloads
    fake = SyntheticExecutor(queue, node, 1)
    monkeypatch.setattr(service.contributors.records, "authenticate", fake.authenticate)
    now = time.time()
    clock = SimpleNamespace(time=lambda: now, monotonic=time.monotonic)
    monkeypatch.setattr(runner_module, "time", clock)
    monkeypatch.setattr(records_module, "time", clock)
    entered, cancelled, cleanup = asyncio.Event(), asyncio.Event(), asyncio.Event()
    commands = []

    async def source_wait(*_args, **_kwargs):
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            await cleanup.wait()
            raise

    async def exchange(identity, message, check, **kwargs):
        fake.pulse()
        commands.append(message.action)
        if message.action in {"input_status", "input_write"}:
            assert message.action == "input_status", "Blocked source bytes must never be sent."
            check()
            asked = message.objects[0]
            assert now < fake.attempts[asked.attempt_id]["lease_expires_at"]
            item = fake.plans[asked.attempt_id].job.inputs[0]
            return REPLY.validate_python({"version": 1, "id": message.id, "deployment_id": "b" * 32,
                "node_id": identity, "ok": True, "results": [{**asked.model_dump(), "ok": True,
                    "offset": 0, "bytes": item.bytes, "digest": item.digest, "complete": False}]})
        reply = await fake.request(identity, message, check, **kwargs)
        if message.action == "observe":
            for row in reply.results:
                row.attempt.ready = False
                fake.attempts[row.attempt_id]["ready"] = False
        return reply

    monkeypatch.setattr(queue.channel, "request", exchange)
    monkeypatch.setattr(service.datasets, "read", source_wait)
    job = await queue.submit(request, secrets.token_hex(16), actor)
    await queue.runner.node(node["id"])
    await queue.runner.schedule()
    attempt_id = queue.records.get(job["id"]).current_attempt
    closing = None
    try:
        # Each poll gather completes while the source is still waiting. Only the
        # controller/executor clocks advance, so this never sleeps for a lease.
        await asyncio.wait_for(asyncio.gather(queue.runner.node(node["id"])), 3)
        await asyncio.wait_for(entered.wait(), 3)
        original_deadline = fake.attempts[attempt_id]["lease_expires_at"]
        for now in (original_deadline - 10, original_deadline + 10):
            await asyncio.wait_for(asyncio.gather(queue.runner.node(node["id"])), 3)
            assert not queue.runner.lock(node["id"]).locked()
            assert fake.attempts[attempt_id]["lease_expires_at"] > now + 20
        assert commands.count("renew") == 2 and not queue.records.get(job["id"]).cancelled
        assert len(queue.inputs.pending) == 1 and not fake.starts
        current = queue.records.get(job["id"])
        queue.cancel(current.id, current.revision, actor)
        await asyncio.wait_for(cancelled.wait(), 3)
        closing = asyncio.create_task(queue.inputs.close())
        await asyncio.sleep(0)
        assert not closing.done() and len(queue.inputs.pending) == 1
        cleanup.set()
        await asyncio.wait_for(closing, 3)
        assert not queue.inputs.pending and not fake.starts
    finally:
        cleanup.set()
        await queue.inputs.close()
        if closing:
            await closing
