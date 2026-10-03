# SPDX-License-Identifier: Apache-2.0
"""Qualify real local scanner coverage and the dataset-to-workload safety boundary."""

import asyncio
import hashlib
import secrets
import shutil
import zipfile

import pytest
from policy_fixtures import activate, install_pack
from test_execution_ledger import plan as sample_plan
from test_files import listing
from workload_fixtures import contributor
from workload_queue_fixtures import scheduler

from ficc.errors import Failure
from ficc.inspection_store import validate_records
from ficc.workloads.schema import Submission


async def test_local_clamav_coverage_quarantine_and_current_workload_authority(policy_console, tmp_path):
    if shutil.which("clamscan") is None:
        pytest.skip("The optional local ClamAV engine is not installed.")
    client, service, material = policy_console
    activate(client, install_pack(client, material))
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    root_path = tmp_path / "inputs"
    root_path.mkdir()
    marker = b"FICC harmless scanner qualification marker, not executable.\n"
    (root_path / "detected.txt").write_bytes(marker)
    (root_path / "clean.txt").write_bytes(b"Ordinary clean inspection fixture.\n")
    with zipfile.ZipFile(root_path / "limited.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("expanded.txt", b"ordinary expanded content\n" * 2048)
    rules = tmp_path / "fixture.ndb"
    rules.write_text("FICC.Qualification.Marker:0:*:" + marker.hex() + "\n")
    root = await service.files.register(str(root_path), "Inspection fixture")
    configured = client.put("/api/v1/inspection-settings", json={"provider": "clamav", "configuration": {
        "database": str(rules), "max_file_bytes": 1048576, "max_scan_bytes": 4096}, "memory_bytes": 268435456,
        "temp_bytes": 16777216, "seconds": 30})
    assert configured.status_code == 200, configured.text
    entries = {item["name"]: item for item in (await listing(service, actor.id, root))["entries"]}

    def register(name, *, parents=()):
        response = client.post("/api/v1/datasets", headers={"Idempotency-Key": secrets.token_hex(16)}, json={
            "name": name, "format": "binary", "schema": {"fields": []},
            "sources": [{"root_id": root["id"], "entry_id": entries[name]["entry_id"]}],
            "provenance": {"input_dataset_ids": list(parents)}})
        assert response.status_code == 201, response.text
        return response.json()

    def controls(dataset, **changes):
        current = client.get(f"/api/v1/datasets/{dataset['id']}/safety").json()["controls"]
        body = {key: current[key] for key in ("revision", "sensitive", "inspection_required", "quarantined")}
        response = client.put(f"/api/v1/datasets/{dataset['id']}/safety", json={**body, **changes, "reason": "Qualification policy decision"})
        assert response.status_code == 200, response.text
        return response.json()

    async def inspect(dataset):
        response = client.post(f"/api/v1/datasets/{dataset['id']}/inspections", headers={"Idempotency-Key": secrets.token_hex(16)})
        assert response.status_code == 202, response.text
        identity = response.json()["id"]
        async with asyncio.timeout(40):
            while (result := client.get(f"/api/v1/inspections/{identity}").json())["state"] != "completed":
                await asyncio.sleep(0.02)
        return result, client.get(f"/api/v1/inspections/{identity}/files").json()["files"]

    clean, detected, limited = (register(name) for name in ("clean.txt", "detected.txt", "limited.zip"))
    controls(clean, inspection_required=True)
    before = clean["manifest_digest"]
    result, files = await inspect(clean)
    assert result["outcome"] == "no_detection", (result, files)
    assert files[0]["engine"]["version"].startswith("ClamAV ")
    assert files[0]["signatures"]["files"][0]["sha256"] == hashlib.sha256(rules.read_bytes()).hexdigest()
    assert client.get(f"/api/v1/datasets/{clean['id']}").json()["manifest_digest"] == before
    assert (await service.datasets.inputs(clean["id"], actor.id))["manifest_digest"] == before
    missing = rules.with_suffix(".unavailable")
    rules.rename(missing)
    try:
        with pytest.raises(Failure, match="blocked"):
            await service.datasets.inputs(clean["id"], actor.id)
    finally:
        missing.rename(rules)

    scheduler(service.workloads)
    managed = contributor(service, actor.project_id)
    voluntary = contributor(service, actor.project_id, index=1, mode="voluntary")
    request = Submission(job=sample_plan(0).job, node_ids=[managed["id"], voluntary["id"]],
                         dataset={"id": clean["id"], "manifest_digest": before})
    job = service.workloads.records.get((await service.workloads.submit(request, secrets.token_hex(16), actor))["id"])
    assert not job.request.job.sensitive
    controls(clean, sensitive=True)
    # An already admitted job is checked again at delivery/lease-renewal authority.
    with pytest.raises(Failure, match="approved managed"):
        service.workloads.authority.check(job, voluntary["id"], enforcement=True)
    service.workloads.authority.check(job, managed["id"], enforcement=True)
    bound = service.workloads.records.get((await service.workloads.submit(request, secrets.token_hex(16), actor))["id"])
    assert bound.request.job.sensitive, "A false user label cannot downgrade current dataset sensitivity."

    result, files = await inspect(detected)
    assert result["outcome"] == "detected" and files[0]["findings"], (result, files)
    assert (root_path / "detected.txt").read_bytes() == marker
    with pytest.raises(Failure, match="blocked"):
        await service.datasets.read(detected["id"], 0, actor.id, 0)
    bad_request = request.model_copy(update={"dataset": request.dataset.model_copy(update={"id": detected["id"], "manifest_digest": detected["manifest_digest"]})})
    with pytest.raises(Failure, match="blocked"):
        await service.workloads.submit(bad_request, secrets.token_hex(16), actor)
    alias = register("detected.txt")
    assert alias["safety"]["quarantined"] and alias["safety"]["blocked"]
    policy = client.get(f"/api/v1/datasets/{detected['id']}/safety").json()
    response = client.put(f"/api/v1/datasets/{detected['id']}/exemption", json={"revision": policy["controls"]["revision"],
        "enabled": True, "expires_at": None, "reason": "Explicit harmless fixture exemption"})
    assert response.status_code == 200 and response.json()["exempt"], response.text
    assert (await service.datasets.read(detected["id"], 0, actor.id, 0))[1] == marker
    assert client.get(f"/api/v1/datasets/{alias['id']}/safety").json()["blocked"], "Exemption is not inherited trust."

    controls(limited, inspection_required=True)
    pending = await service.inspections.submit(limited["id"], secrets.token_hex(16), actor.id)
    cancelled = await service.inspections.cancel(pending["id"], actor.id)
    assert cancelled["outcome"] == "incomplete"
    with pytest.raises(Failure, match="blocked"):
        await service.datasets.inputs(limited["id"], actor.id)
    result, files = await inspect(limited)
    assert result["outcome"] == "incomplete" and files[0]["coverage"]["reasons"], (result, files)
    with pytest.raises(Failure, match="blocked"):
        await service.datasets.inputs(limited["id"], actor.id)
    # Late quarantine stops an existing job's next read and authority renewal.
    controls(clean, quarantined=True)
    with pytest.raises(Failure, match="blocked"):
        service.workloads.authority.check(job, managed["id"], enforcement=True)
    with pytest.raises(Failure, match="blocked"):
        await service.datasets.read(clean["id"], 0, lambda: service.workloads.authority.current(job.delegation), 0)
    assert any(event["action"] == "dataset.exemption" for event in service.store.events())
    validate_records(service.store.db)
