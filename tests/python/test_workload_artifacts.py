# SPDX-License-Identifier: Apache-2.0
"""Publish fenced synthetic executor output through real registered-file transfers."""

import asyncio
import base64
import hashlib
import secrets

import pytest
from ficc_node.file_access import CHUNK
from policy_fixtures import activate, install_pack
from test_datasets import registered
from test_execution_ledger import plan as sample_plan
from test_identity_projects import member
from test_transfers import location
from workload_fixtures import INSTALLATION, contributor, placement, result
from workload_queue_fixtures import scheduler

from ficc.errors import Failure
from ficc.execution.spec import Output, digest
from ficc.execution.wire import REPLY
from ficc.workloads.artifacts import Publication, Publications
from ficc.workloads.schema import Submission


async def completed_workload(console, tmp_path, monkeypatch, data, *, lineage=False):
    client, service, material = console
    activate(client, install_pack(client, material))
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    node = contributor(service, actor.project_id)
    queue = service.workloads
    scheduler(queue)
    path = tmp_path / "published"
    path.mkdir()
    root = await service.files.register(str(path), "Published workload output")
    dataset = None
    if lineage:
        (path / "input.csv").write_bytes(b"value\n3\n")
        dataset, _ = await registered(service, actor.id, root)
    job_spec = sample_plan(0).job
    job_spec.outputs = [Output(name="result", path="result.bin")]
    body = {"job": job_spec, "node_ids": [node["id"]]}
    if dataset:
        body["dataset"] = {"id": dataset["id"], "manifest_digest": dataset["manifest_digest"]}
    submitted = await queue.submit(Submission(**body), secrets.token_hex(16), actor)
    job = queue.records.get(submitted["id"])
    plan, lease = placement(job, node["id"])
    queue.records.reserve(plan, lease, INSTALLATION, plan.job.limits)
    queue.records.observation(result(plan), node["id"], INSTALLATION)
    control = {"identity": digest({"fixture": plan.attempt_id}), "reads": [], "after_read": None}

    async def exchange(identity, message, check, **_kwargs):
        assert identity == node["id"] and message.action == "collect"
        check()
        rows = []
        for asked in message.reads:
            assert asked.attempt_id == plan.attempt_id and asked.plan_digest == plan.digest()
            assert asked.length <= CHUNK
            control["reads"].append((asked.offset, asked.length))
            chunk = data[asked.offset:asked.offset + asked.length]
            rows.append({**asked.model_dump(exclude={"length"}), "ok": True, "data": base64.b64encode(chunk).decode(),
                         "next_offset": asked.offset + len(chunk), "total_bytes": len(data),
                         "eof": asked.offset + len(chunk) == len(data), "complete": True, "identity": control["identity"]})
        if control["after_read"]:
            control["after_read"]()
        check()
        return REPLY.validate_python({"version": 1, "id": message.id, "deployment_id": plan.deployment_id,
                                      "node_id": node["id"], "ok": True, "results": rows})

    monkeypatch.setattr(queue.channel, "request", exchange)
    job = queue.records.get(job.id)
    request = {"revision": job.revision, "object": "output:result", "name": "result.bin",
               "destination": location(service, root), "dataset": None}
    return service, actor, job, root, path, request, control, dataset


async def settled(service, identity):
    await asyncio.gather(*list(service.transfers.tasks.values()))
    return service.transfers.store.get(identity)


@pytest.mark.parametrize("data", [b"", bytes(range(256)) * 2100], ids=["empty", "multiple-chunks"])
async def test_publish_verified_file_dataset_origin_and_idempotency(policy_console, tmp_path, monkeypatch, data):
    service, actor, job, _root, path, request, control, parent = await completed_workload(policy_console, tmp_path, monkeypatch, data, lineage=True)
    publications = service.workloads.artifacts
    request["dataset"] = {"name": "Workload result", "format": "binary", "schema": {"fields": []}}
    key = secrets.token_hex(16)
    accepted = await publications.publish(job.id, request, key, actor)
    identity = accepted["transfer"]["id"]
    with pytest.raises(Failure, match="Finish or cancel"):
        await service.workloads.release(job.id, job.revision, actor)
    saved = await settled(service, identity)
    item = saved["items"][0]
    assert saved["state"] == "succeeded" and (path / "result.bin").read_bytes() == data
    assert item["artifact"]["verified"] and item["artifact"]["digest"] == hashlib.sha256(data).hexdigest()
    assert item["dataset"], item.get("dataset_error")
    manifest = service.datasets.get(item["dataset"]["id"], actor.id)
    assert manifest["origin"]["attempt_id"] == job.current_attempt
    assert manifest["origin"]["input_dataset"] == {"id": parent["id"], "manifest_digest": parent["manifest_digest"]}
    assert manifest["origin"]["transfer_id"] == identity and manifest["origin"]["object"] == "output:result"
    assert manifest["provenance"]["input_dataset_ids"] == [parent["id"]]
    assert all(length <= CHUNK for _offset, length in control["reads"])
    assert (await publications.publish(job.id, request, key, actor))["transfer"]["id"] == identity
    with pytest.raises(Failure) as conflict:
        await publications.publish(job.id, {**request, "name": "different"}, key, actor)
    assert conflict.value.code == "idempotency_conflict"
    with pytest.raises(Failure) as exists:
        await publications.publish(job.id, request, secrets.token_hex(16), actor)
    assert exists.value.code == "destination_conflict" and (path / "result.bin").read_bytes() == data
    publications.require_releasable(job.id, removing=True)


@pytest.mark.parametrize("changed", [False, True])
async def test_interrupted_copy_reconciles_prefix_or_refuses_changed_source(policy_console, tmp_path, monkeypatch, changed):
    data = b"a" * CHUNK + b"b" * CHUNK + b"tail"
    service, actor, job, _root, path, request, control, _parent = await completed_workload(policy_console, tmp_path, monkeypatch, data)
    original = service.transfers.destination
    writes = []

    async def lost(operation, item, action, **values):
        response = await original(operation, item, action, **values)
        if action == "transfer.write":
            writes.append(values["offset"])
            if len(writes) == 1:
                raise Failure("unreachable", "The chunk acknowledgement was lost.", 502)
        return response

    monkeypatch.setattr(service.transfers, "destination", lost)
    accepted = await service.workloads.artifacts.publish(job.id, request, secrets.token_hex(16), actor)
    identity = accepted["transfer"]["id"]
    saved = await settled(service, identity)
    assert saved["state"] == "interrupted" and not (path / "result.bin").exists()
    service.workloads.artifacts = Publications(service.workloads)
    if changed:
        control["identity"] = digest({"changed": True})
    await service.workloads.artifacts.change(job.id, identity, actor.id, resume=True)
    saved = await settled(service, identity)
    if changed:
        assert saved["state"] == "interrupted" and saved["items"][0]["error"]["code"] == "source_changed"
        assert writes == [0]
        await service.workloads.artifacts.change(job.id, identity, actor.id, discard=True)
        service.workloads.artifacts.require_releasable(job.id)
        assert not (path / "result.bin").exists()
    else:
        assert saved["state"] == "succeeded" and writes == [0, CHUNK, 2 * CHUNK]
        assert (path / "result.bin").read_bytes() == data


async def test_uncertain_commit_reconciles_same_destination_without_source_replay(policy_console, tmp_path, monkeypatch):
    data = b"verified result"
    service, actor, job, _root, path, request, control, _parent = await completed_workload(policy_console, tmp_path, monkeypatch, data)
    original = service.transfers.destination

    async def lost(operation, item, action, **values):
        response = await original(operation, item, action, **values)
        if action == "transfer.commit":
            raise Failure("unreachable", "The publication acknowledgement was lost.", 502)
        return response

    monkeypatch.setattr(service.transfers, "destination", lost)
    accepted = await service.workloads.artifacts.publish(job.id, request, secrets.token_hex(16), actor)
    identity = accepted["transfer"]["id"]
    saved = await settled(service, identity)
    assert saved["state"] == "unknown" and (path / "result.bin").read_bytes() == data
    inode, reads = (path / "result.bin").stat().st_ino, list(control["reads"])
    with pytest.raises(Failure, match="Reconcile"):
        await service.workloads.artifacts.change(job.id, identity, actor.id, discard=True)
    with pytest.raises(Failure, match="Finish or cancel"):
        service.workloads.artifacts.require_releasable(job.id)
    await service.workloads.artifacts.change(job.id, identity, actor.id, resume=True)
    saved = await settled(service, identity)
    assert saved["state"] == "succeeded" and saved["items"][0]["artifact"]["verified"]
    assert control["reads"] == reads and (path / "result.bin").stat().st_ino == inode


async def test_current_credentials_and_project_are_required_during_publication(policy_console, tmp_path, monkeypatch):
    service, actor, job, _root, path, request, control, _parent = await completed_workload(policy_console, tmp_path, monkeypatch, b"private" * 50000)
    accepted = await service.workloads.artifacts.publish(job.id, request, secrets.token_hex(16), actor)
    identity = accepted["transfer"]["id"]
    control["after_read"] = lambda: service.auth.revoke(actor.id)
    saved = await settled(service, identity)
    assert saved["state"] == "interrupted" and not (path / "result.bin").exists()
    with pytest.raises(Failure):
        service.workloads.artifacts.all(job.id, actor.id)
    _user, _project, outsider, _headers = member(service, "Other publication project")
    with pytest.raises(Failure):
        service.workloads.artifacts.view(saved, outsider.id)
    assert saved["items"][0]["offset"] == 0


async def test_dataset_registration_recovers_after_file_and_manifest_commits(policy_console, tmp_path, monkeypatch):
    service, actor, job, _root, path, request, control, _parent = await completed_workload(policy_console, tmp_path, monkeypatch, b"dataset result")
    request["dataset"] = {"name": "Result dataset", "format": "binary", "schema": {"fields": []}}
    original = service.datasets.create

    async def lost(*args, **kwargs):
        await original(*args, **kwargs)
        raise Failure("receipt_unknown", "The dataset response was interrupted.", 502)

    monkeypatch.setattr(service.datasets, "create", lost)
    accepted = await service.workloads.artifacts.publish(job.id, request, secrets.token_hex(16), actor)
    identity = accepted["transfer"]["id"]
    saved = await settled(service, identity)
    assert saved["state"] == "succeeded" and saved["items"][0]["dataset_error"]["code"] == "receipt_unknown"
    with pytest.raises(Failure, match="Finish or cancel"):
        service.workloads.artifacts.require_releasable(job.id, removing=True)
    reads = list(control["reads"])
    attempt = service.workloads.records.attempt(job.current_attempt)
    service.workloads.records.observation(attempt.observed.model_copy(update={"state": "released"}), attempt.node_id, INSTALLATION)
    monkeypatch.setattr(service.datasets, "create", original)
    final = await service.workloads.artifacts.change(job.id, identity, actor.id, resume=True)
    assert final["dataset"] and final["dataset_error"] is None
    assert control["reads"] == reads and (path / "result.bin").read_bytes() == b"dataset result"
    assert service.store.db.execute("SELECT count(*) FROM datasets").fetchone()[0] == 1
    service.workloads.artifacts.require_releasable(job.id, removing=True)


async def test_partial_can_be_cancelled_after_source_cleanup_becomes_unknown(policy_console, tmp_path, monkeypatch):
    service, actor, job, _root, path, request, control, _parent = await completed_workload(policy_console, tmp_path, monkeypatch, b"retained")
    accepted = await service.workloads.artifacts.publish(job.id, request, secrets.token_hex(16), actor)
    attempt = service.workloads.records.attempt(job.current_attempt)
    def changed():
        service.workloads.records.observation(attempt.observed.model_copy(update={"state": "unknown", "cleanup_confirmed": False}), attempt.node_id, INSTALLATION)
    control["after_read"] = changed
    identity = accepted["transfer"]["id"]
    saved = await settled(service, identity)
    assert saved["state"] == "interrupted" and saved["items"][0]["error"]["code"] == "output_unavailable"
    final = await service.workloads.artifacts.change(job.id, identity, actor.id, discard=True)
    assert final["transfer"]["state"] == "cancelled" and not (path / "result.bin").exists()
    service.workloads.artifacts.require_releasable(job.id)


async def test_destination_race_is_preserved_and_conflicted_copy_can_be_discarded(policy_console, tmp_path, monkeypatch):
    service, actor, job, _root, path, request, _control, _parent = await completed_workload(policy_console, tmp_path, monkeypatch, b"new output")
    original = service.transfers.destination
    async def race(operation, item, action, **values):
        if action == "transfer.commit":
            (path / "result.bin").write_bytes(b"concurrent file")
        return await original(operation, item, action, **values)
    monkeypatch.setattr(service.transfers, "destination", race)
    accepted = await service.workloads.artifacts.publish(job.id, request, secrets.token_hex(16), actor)
    identity = accepted["transfer"]["id"]
    saved = await settled(service, identity)
    assert saved["state"] == "unknown" and saved["items"][0]["error"]["code"] == "destination_changed"
    final = await service.workloads.artifacts.change(job.id, identity, actor.id, resume=True)
    assert final["transfer"]["state"] == "interrupted"
    final = await service.workloads.artifacts.change(job.id, identity, actor.id, discard=True)
    assert final["transfer"]["state"] == "cancelled" and (path / "result.bin").read_bytes() == b"concurrent file"


def test_publication_schema_does_not_accept_host_paths_or_origin_claims():
    with pytest.raises(ValueError):
        Publication.model_validate({"revision": 1, "object": "../../secret", "name": "output",
            "destination": {"root_id": "a" * 32, "entry_id": "opaque"}, "origin": {"kind": "workload"}})
