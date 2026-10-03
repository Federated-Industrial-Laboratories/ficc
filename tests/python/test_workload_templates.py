# SPDX-License-Identifier: Apache-2.0
"""Protect project recipe sharing and exclude credentials and execution authority."""

from test_execution_ledger import plan as sample_plan
from test_identity_projects import member

from ficc.execution.spec import digest
from ficc.workloads.templates import validate_records


def test_shared_runbook_versions_exclude_authority_and_preserve_content(console):
    client, service = console
    _user, project, _principal, author = member(service, "Runbook author")
    _user2, _project2, _principal2, colleague = member(service, "Colleague", project=project)
    _user3, _project3, _principal3, outside = member(service, "Other project")
    job = sample_plan(0).job.model_dump()
    job["payload"]["environment"] = {"PRIVATE_TOKEN": "must-not-be-shared"}
    job["limits"]["gpu_devices"] = ["GPU-private-identity"]
    job["inputs"] = [{"id": "a" * 32, "name": "private.bin", "bytes": 1, "digest": "sha256:" + "b" * 64}]
    body = {"name": "Dataset conversion", "instructions": "Select the approved input dataset.", "job": job}
    first = client.post("/api/v1/workload-templates", headers=author, json=body)
    assert first.status_code == 201, first.text
    value = first.json()
    assert value["job"]["inputs"] == [] and value["job"]["payload"]["environment"] == {}
    assert value["job"]["limits"]["gpu_devices"] == []
    assert "must-not-be-shared" not in first.text and "private.bin" not in first.text
    assert value["digest"] == digest({"job": value["job"], "instructions": body["instructions"]})
    second = client.post("/api/v1/workload-templates", headers=author, json=body).json()
    assert second["version"] == 2 and second["digest"] == value["digest"]
    assert client.get("/api/v1/workload-templates", headers=colleague).json()["templates"] == [value, second]
    assert client.get("/api/v1/workload-templates", headers=outside).json()["templates"] == []
    path = "/api/v1/workload-templates/" + value["id"]
    assert client.delete(path, headers=outside).status_code == 404
    validate_records(service.store.db)
    assert client.delete(path, headers=colleague).status_code == 200
    assert client.get("/api/v1/workload-templates", headers=author).json()["templates"] == [second]
