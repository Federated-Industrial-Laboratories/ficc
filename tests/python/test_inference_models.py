# SPDX-License-Identifier: Apache-2.0
"""Verify immutable model publication, project boundaries and metadata-only recovery."""
import base64
import hashlib

import pytest

from ficc.backup import export, restore
from ficc.errors import Failure
from ficc.models.cache import Cache
from ficc.models.schema import File
from ficc.service import Service
from ficc.settings import Settings


def manifest(data=b"GGUF fixture bytes"):
    return {"name": "Fixture", "revision": "source-commit", "licence": "Apache-2.0", "format": "gguf",
            "entrypoint": "model.gguf", "files": [{"name": "model.gguf", "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "bytes": len(data)}]}


def test_official_model_redirect_hosts_remain_exact_and_overridable():
    from ficc.models.sources import DEFAULT_HOSTS, allowed
    allowed("https://us.aws.cdn.hf.co/immutable-object", DEFAULT_HOSTS)
    for url in ("https://us.aws.cdn.hf.co.attacker.example/object",
                "https://attacker.example@us.aws.cdn.hf.co/object",
                "http://us.aws.cdn.hf.co/object", "https://us.aws.cdn.hf.co:444/object"):
        with pytest.raises(Failure, match="allowlist"):
            allowed(url, DEFAULT_HOSTS)
    with pytest.raises(Failure, match="allowlist"):
        allowed("https://us.aws.cdn.hf.co/immutable-object", ["models.example"])


def test_cache_resume_and_digest_failure_never_publish(tmp_path):
    data = b"model-content" * 100
    item = File.model_validate(manifest(data)["files"][0])
    cache = Cache(tmp_path / "models")
    assert cache.write(item, 0, data[:100])["offset"] == 100
    recovered = Cache(tmp_path / "models")
    with pytest.raises(Failure, match="durable"):
        recovered.write(item, 0, data)
    assert recovered.write(item, 100, data[100:])["complete"]
    assert recovered.read(item, 37, 71) == data[37:108]
    bad = File.model_validate({**item.model_dump(), "digest": "sha256:" + "0" * 64})
    with pytest.raises(Failure, match="digest"):
        recovered.write(bad, 0, data)
    assert not recovered.path(bad).exists() and not recovered.path(bad, True).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [True, False])
async def test_full_length_partial_recovers_after_final_write_before_publish(tmp_path, valid):
    data = b"durable model bytes"
    item = File.model_validate(manifest(data)["files"][0])
    cache = Cache(tmp_path / "models")
    cache.path(item, True).write_bytes(data if valid else b"x" * len(data))
    # Publication may also have stopped after chmod but before its rename.
    cache.path(item, True).chmod(0o400)
    recovered = Cache(tmp_path / "models")
    assert recovered.status(item) == {"offset": len(data), "complete": False, "bytes": len(data)}
    if valid:
        assert (await recovered.write_async(item, len(data), b""))["complete"]
        assert recovered.read(item, 0, len(data)) == data
    else:
        with pytest.raises(Failure, match="digest"):
            await recovered.write_async(item, len(data), b"")
        assert not recovered.path(item).exists() and not recovered.path(item, True).exists()


@pytest.mark.asyncio
async def test_acquisition_finalizes_retained_bytes_without_http(tmp_path, monkeypatch):
    from ficc.models import sources
    service = Service(Settings(state_dir=tmp_path / "state", control=False))
    try:
        _, actor = service.auth.issue("token")
        data = b"retained acquisition bytes"
        model = service.models.create(manifest(data), actor)
        item = File.model_validate(model["manifest"]["files"][0])
        service.models.cache_for(model).path(item, True).write_bytes(data)
        def unexpected(*args, **kwargs):
            raise AssertionError("A complete retained partial needs no HTTP range.")
        monkeypatch.setattr(sources.httpx.AsyncClient, "stream", unexpected)
        state = service.models.downloads[model["id"]] = {}
        await sources.acquire(service.models, model["id"], actor)
        assert state["state"] == "complete"
        assert service.models.view(model)["ready"]
    finally:
        service.close()


def test_upload_finalizes_only_a_full_length_retained_partial(console):
    client, service = console
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    data = b"retained upload bytes"
    model = service.models.create(manifest(data), actor)
    item = File.model_validate(model["manifest"]["files"][0])
    path = f"/api/v1/models/{model['id']}/files/0/bytes"
    headers = {"Content-Type": "application/octet-stream"}
    cache = service.models.cache_for(model)
    cache.path(item, True).write_bytes(data[:3])
    assert client.post(path + "?offset=3", content=b"", headers=headers).status_code == 422
    assert client.post(path + f"?offset={len(data)}", content=b"", headers=headers).status_code == 409
    cache.path(item, True).write_bytes(data)
    result = client.post(path + f"?offset={len(data)}", content=b"", headers=headers)
    assert result.status_code == 200 and result.json()["complete"]


@pytest.mark.asyncio
async def test_cancelled_upload_waits_for_its_durable_write(tmp_path, monkeypatch):
    import asyncio
    import threading
    cache = Cache(tmp_path / "models")
    item = File.model_validate(manifest(b"full-model")["files"][0])
    entered, release = threading.Event(), threading.Event()
    original = cache.write
    def delayed(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(cache, "write", delayed)
    task = asyncio.create_task(cache.write_async(item, 0, b"full-"))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        await asyncio.sleep(0.02)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cache.status(item)["offset"] == 5
    assert await cache.write_async(item, 5, b"model") == {"offset": 10, "complete": True, "bytes": 10}


def test_cache_status_and_other_reads_do_not_wait_for_large_verification(tmp_path, monkeypatch):
    import concurrent.futures
    import threading
    data = b"verified bytes"
    item = File.model_validate(manifest(data)["files"][0])
    other = File.model_validate(manifest(b"other bytes")["files"][0])
    cache = Cache(tmp_path / "models")
    cache.write(other, 0, b"other bytes")
    entered, release = threading.Event(), threading.Event()
    original = hashlib.file_digest
    def delayed_digest(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)
    monkeypatch.setattr(hashlib, "file_digest", delayed_digest)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(cache.write, item, 0, data)
        try:
            assert entered.wait(2)
            status = pool.submit(cache.status, item).result(timeout=1)
            assert not status["complete"] and status["offset"] == len(data)
            assert pool.submit(cache.read, other, 0, 11).result(timeout=1) == b"other bytes"
            with pytest.raises(Failure, match="verification"):
                cache.evict(item)
        finally:
            release.set()
        assert writer.result(timeout=2)["complete"]


def test_api_upload_and_project_token_refusal(console):
    client, service = console
    data = b"GGUF fixture bytes"
    response = client.post("/api/v1/models", json=manifest(data))
    assert response.status_code == 201
    identity = response.json()["id"]
    response = client.post(f"/api/v1/models/{identity}/files/0", json={"offset": 0, "data": base64.b64encode(data).decode()})
    assert response.status_code == 200 and response.json()["complete"]
    assert client.get(f"/api/v1/models/{identity}").json()["ready"]
    token, _ = service.auth.issue("token", scopes=["inference:invoke"])
    assert client.get(f"/api/v1/models/{identity}", headers={"Authorization": "Bearer " + token}).status_code == 403
    assert client.get("/api/v1/inference").json()["services"] == []


def test_binary_model_upload_is_bounded_authorized_and_resumable(console):
    client, service = console
    data = b"weights" * 300000
    identity = client.post("/api/v1/models", json=manifest(data)).json()["id"]
    path = f"/api/v1/models/{identity}/files/0/bytes"
    headers = {"Content-Type": "application/octet-stream"}
    token, _ = service.auth.issue("token", scopes=["inference:invoke"])
    assert client.post(path + "?offset=0", content=b"x", headers={**headers, "Authorization": "Bearer " + token}).status_code == 403
    assert client.post(path + "?offset=0", content=b"x", headers={**headers, "Content-Length": str(16 * 1024 * 1024 + 1)}).status_code == 413
    first = client.post(path + "?offset=0", content=data[:1500000], headers=headers)
    assert first.status_code == 200 and first.json()["offset"] == 1500000 and not first.json()["complete"]
    assert client.post(path + "?offset=0", content=data, headers=headers).status_code == 409
    complete = client.post(path + "?offset=1500000", content=data[1500000:], headers=headers)
    assert complete.status_code == 200 and complete.json()["complete"]


def test_backup_contains_model_metadata_and_excludes_weights(tmp_path):
    state = tmp_path / "state"
    service = Service(Settings(state_dir=state, control=False))
    _, actor = service.auth.issue("token")
    data = b"not-in-the-backup" * 100
    model = service.models.create(manifest(data), actor)
    item = File.model_validate(model["manifest"]["files"][0])
    service.models.cache_for(model).write(item, 0, data)
    service.close()
    bundle, restored = tmp_path / "bundle", tmp_path / "restored"
    export(state, bundle)
    assert not (bundle / "models").exists()
    restore(bundle, restored, True)
    loaded = Service(Settings(state_dir=restored, control=False))
    try:
        _, reader = loaded.auth.issue("token")
        found = loaded.models.get(model["id"], reader)
        assert found["manifest_digest"] == model["manifest_digest"]
        assert not loaded.models.view(found)["ready"]
    finally:
        loaded.close()


def test_invocation_token_is_bound_to_one_service_and_revoked_on_removal(console):
    import secrets
    import time

    from test_execution_ledger import plan

    from ficc.inference.schema import Record, Specification

    client, service = console
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    model = service.models.create(manifest(), actor)
    fixture = plan(0)
    values = []
    for alias in ("first", "second"):
        spec = Specification(alias=alias, model_id=model["id"], engine="llama_cpp", runtime=fixture.job.runtime,
                             executable="/server", placements=[{"node_id": fixture.node_id, "limits": fixture.job.limits}])
        value = Record(id=secrets.token_hex(16), project_id=actor.project_id, subject_id=actor.subject_id, actor=actor.id,
                       spec=spec, generation=1, desired="stopped", state="stopped", reason=None, workloads=[],
                       created_at=time.time(), revision=1).model_dump()
        service.inference.records.save(value)
        values.append(value)
    token = service.inference.token(values[0]["id"], actor)
    scoped = service.auth.resolve(token["token"])
    assert service.inference.get(values[0]["id"], scoped, "inference:invoke")["id"] == values[0]["id"]
    with pytest.raises(Failure, match="credential"):
        service.inference.get(values[1]["id"], scoped, "inference:invoke")
    with pytest.raises(Failure):
        service.models.get(model["id"], scoped)
    # Recreate the manager to check that the restriction survives controller restart.
    from ficc.inference.service import Inference
    service.inference = Inference(service)
    with pytest.raises(Failure):
        service.inference.get(values[1]["id"], scoped, "inference:invoke")
    import asyncio
    current = service.inference.records.get(values[0]["id"])
    asyncio.run(service.inference.control(current["id"], "remove", current["revision"], actor))
    with pytest.raises(Failure):
        service.auth.resolve(token["token"])


def test_ssh_jobs_and_contributor_attempts_share_gpu_admission(console):
    import secrets

    from test_execution_ledger import offer
    from workload_fixtures import INSTALLATION, contributor, placement, result, submitted

    from ficc.job_store import JobStore

    client, service = console
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    node = contributor(service, actor.project_id)
    records = service.workloads.records
    job = submitted(service, actor, node)
    plan, lease = placement(job, node["id"])
    records.reserve(plan, lease, INSTALLATION, offer(1).limits)
    operation = {"id": secrets.token_hex(16), "actor": actor.id, "subject_id": actor.subject_id,
                 "project_id": actor.project_id, "key": "cross-path-admission", "digest": "fixture",
                 "targets": [{"node_id": "ssh-representation", "state": "queued", "reservations": [{"uuid": plan.job.limits.gpu_devices[0], "memory_bytes": 1024}]}]}
    with pytest.raises(Failure, match="reserved"):
        JobStore(service.store).insert(operation)
    records.observation(result(plan), node["id"], INSTALLATION)
    records.observation(result(plan, "released"), node["id"], INSTALLATION)
    JobStore(service.store).insert(operation)
    second = submitted(service, actor, node)
    with pytest.raises(Failure, match="SSH job"):
        records.reserve(*placement(second, node["id"]), INSTALLATION, offer(1).limits)


def test_service_restart_requires_explicit_unknown_acknowledgement_and_release(console):
    import secrets
    import time

    from test_execution_ledger import offer
    from workload_fixtures import INSTALLATION, contributor, placement, result, submitted

    from ficc.inference.schema import Record, Specification

    client, service = console
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    model = service.models.create(manifest(), actor)
    node = contributor(service, actor.project_id)
    queue = service.workloads
    jobs = []
    plans = []
    for state in ("cancelled", "unknown"):
        job = submitted(service, actor, node)
        plan, lease = placement(job, node["id"])
        queue.records.reserve(plan, lease, INSTALLATION, offer(1).limits)
        queue.records.observation(result(plan, state), node["id"], INSTALLATION)
        queue.records.observation(result(plan, "released"), node["id"], INSTALLATION)
        jobs.append(job)
        plans.append(plan)
    spec = Specification(alias="recovery", model_id=model["id"], engine="llama_cpp", runtime=plans[0].job.runtime,
                         executable="/server", placements=[{"node_id": node["id"], "limits": plans[0].job.limits}])
    record = Record(id=secrets.token_hex(16), project_id=actor.project_id, subject_id=actor.subject_id, actor=actor.id,
                    spec=spec, generation=1, desired="stopped", state="stopped", reason=None, workloads=[job.id for job in jobs],
                    created_at=time.time(), revision=1).model_dump()
    service.inference.records.save(record)
    path = "/api/v1/inference/" + record["id"] + "/control/"
    refused = client.post(path + "start", json={"revision": 1})
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "inference_unknown_outcome"
    assert [queue.records.get(job.id).state for job in jobs] == ["cancelled", "unknown"]
    assert client.post(path + "stop", json={"revision": 1, "acknowledge_unknown": True}).status_code == 422
    assert client.post(path + "start", json={"revision": 0, "acknowledge_unknown": True}).status_code == 409
    # Acknowledgement cannot override an unreleased earlier attempt.
    pending = queue.records.attempt(plans[0].attempt_id)
    pending.state = "unknown"
    queue.records.save_attempt(pending)
    assert client.post(path + "start", json={"revision": 1, "acknowledge_unknown": True}).status_code == 409
    assert [queue.records.get(job.id).state for job in jobs] == ["cancelled", "unknown"]
    pending.state = "released"
    queue.records.save_attempt(pending)
    started = client.post(path + "start", json={"revision": 1, "acknowledge_unknown": True})
    assert started.status_code == 200, started.text
    assert started.json()["state"] == "pending" and started.json()["generation"] == 2
    assert [queue.records.get(job.id).state for job in jobs] == ["queued", "queued"]
    assert [queue.records.attempt(plan.attempt_id).state for plan in plans] == ["released", "released"]
