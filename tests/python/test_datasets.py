# SPDX-License-Identifier: Apache-2.0
"""Protect dataset identity, project isolation, durable authority and recovery."""

import hashlib
import json
from contextlib import closing

import pytest
from test_files import files_fixture as files_fixture
from test_files import listing
from test_identity_projects import member

from ficc.backup import export, restore
from ficc.dataset_store import validate_records
from ficc.datasets import Datasets
from ficc.errors import Failure
from ficc.store import Store


async def registered(service, actor, root, *, parents=()):
    entry = (await listing(service, actor, root))["entries"][0]
    body = {"name": "Measurements", "format": "csv", "schema": {"fields": [{"name": "value", "type": "int64", "nullable": False}]},
            "sources": [{"root_id": root["id"], "entry_id": entry["entry_id"]}],
            "provenance": {"description": "Instrument snapshot", "input_dataset_ids": list(parents)}}
    return await service.datasets.create(body, "dataset-request-key-01", actor), body


async def test_dataset_version_identity_recovery_and_changed_source(files_fixture, tmp_path):
    service, actor, root, path = files_fixture
    service.datasets = Datasets(service)
    data = b"value\n17\n"
    (path / "values.csv").write_bytes(data)
    result, body = await registered(service, actor, root)
    source = result["files"][0]
    assert source["sha256"] == hashlib.sha256(data).hexdigest() and "reference" not in source
    assert result["schema"]["fields"][0]["type"] == "int64"
    assert (await service.datasets.create(body, "dataset-request-key-01", actor))["id"] == result["id"]
    assert (await service.datasets.inputs(result["id"], actor))["manifest_digest"] == result["manifest_digest"]
    _, content = await service.datasets.read(result["id"], 0, actor, 0)
    assert content == data
    # Controller recovery retains authenticated references without copying source bytes.
    bundle, restored = tmp_path / "backup", tmp_path / "restore"
    export(service.settings.state_dir, bundle)
    restore(bundle, restored, True)
    with closing(Store(restored / "state.sqlite3")) as store:
        validate_records(store.db)
        saved = json.loads(store.db.execute("SELECT value FROM datasets WHERE id=:p0", (result["id"],)).fetchone()[0])
        assert saved["manifest_digest"] == result["manifest_digest"]
    (path / "values.csv").write_bytes(b"value\n99\n")
    with pytest.raises(Failure):
        await service.datasets.inputs(result["id"], actor)
    with pytest.raises(Failure):
        await service.datasets.read(result["id"], 0, actor, 0)


async def test_dataset_project_isolation_and_current_root_authority(files_fixture):
    service, _, root, path = files_fixture
    service.datasets = Datasets(service)
    (path / "values.csv").write_bytes(b"value\n3\n")
    _, project, reader, _ = member(service, "Dataset user")
    _, outside, attacker, _ = member(service, "Other project")
    for target in (project, outside):
        service.auth.resources.save(target["id"], [], [root["id"]], 0)
    result, _ = await registered(service, reader.id, root)
    assert service.datasets.all(attacker.id)["datasets"] == []
    with pytest.raises(Failure) as denied:
        service.datasets.get(result["id"], attacker.id)
    assert denied.value.status == 404
    with pytest.raises(Failure):
        await registered(service, attacker.id, root, parents=[result["id"]])
    service.auth.resources.save(project["id"], [], [], 1)
    assert service.datasets.all(reader.id)["datasets"] == []
    with pytest.raises(Failure):
        await service.datasets.read(result["id"], 0, reader.id, 0)


async def test_dataset_job_authority_callback_and_tampered_manifest(files_fixture):
    service, actor, root, path = files_fixture
    service.datasets = Datasets(service)
    (path / "values.csv").write_bytes(b"value\n3\n")
    result, _ = await registered(service, actor, root)
    principal = service.auth.current(actor)
    service.auth.revoke(actor)
    calls = []
    def authority():
        calls.append(True)
        if len(calls) > 20:
            raise Failure("denied", "The test delegation was revoked.", 403)
        return principal
    assert (await service.datasets.read(result["id"], 0, authority, 0))[1] == b"value\n3\n"
    assert len(calls) >= 4
    calls.extend([True] * 20)
    with pytest.raises(Failure, match="revoked"):
        await service.datasets.read(result["id"], 0, authority, 0)
    saved = service.datasets.store.get(result["id"])
    saved["files"][0]["sha256"] = "0" * 64
    with service.store.lock, service.store.db:
        service.store.db.execute("UPDATE datasets SET value=:p0 WHERE id=:p1", (json.dumps(saved), result["id"]))
    with pytest.raises(ValueError, match="authentication"):
        service.datasets.store.get(result["id"])


async def test_dataset_api_registers_and_verifies_real_source(console, tmp_path):
    client, service = console
    source = tmp_path / "measurements"
    source.mkdir()
    (source / "sample.csv").write_bytes(b"count\n7\n")
    root = await service.files.register(str(source), "Dataset source")
    actor = client.get("/api/v1/session").json()["principal"]["id"]
    entry = (await listing(service, actor, root))["entries"][0]
    body = {"name": "Measurements", "format": "csv", "schema": {"fields": [{"name": "count", "type": "int64"}]},
            "sources": [{"root_id": root["id"], "entry_id": entry["entry_id"]}]}
    response = client.post("/api/v1/datasets", json=body, headers={"Idempotency-Key": "dataset-api-request-01"})
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    assert client.get("/api/v1/datasets").json()["datasets"][0]["id"] == identity
    assert client.post(f"/api/v1/datasets/{identity}/verify", json={}).json()["verified"] is True
    (source / "sample.csv").write_bytes(b"count\n8\n")
    assert client.post(f"/api/v1/datasets/{identity}/verify", json={}).status_code == 409
