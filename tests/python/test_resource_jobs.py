# SPDX-License-Identifier: Apache-2.0
"""Keep durable job receipts private to their project across revocation and dispatch."""

import asyncio

import pytest
from conftest import node
from resource_fixtures import assign
from resource_fixtures import resource_console as resource_console
from test_identity_projects import member
from test_jobs import Remote, request


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_job_receipts_keep_project_ownership_after_credential_removal(resource_console, monkeypatch, count):
    client, service = resource_console
    remote = Remote()
    monkeypatch.setattr(service.ssh, "job", remote.job)
    ids = [f"node-{index}" for index in range(count)]
    for index in range(count):
        service.store.save_node(node(index))
    user, project, principal, headers = member(service, "Submitting operator")
    _, outside, _, attack = member(service, "Separate project")
    assign(client, project, ids)
    assign(client, outside, ids)
    preview = client.post("/api/v1/operation-previews", headers=headers, json=request(count))
    assert preview.status_code == 200, preview.text
    submitted = client.post("/api/v1/operations", headers={**headers, "Idempotency-Key": "project-submission-key"},
                            json={"preview_id": preview.json()["preview_id"]})
    assert submitted.status_code == 202, submitted.text
    operation = submitted.json()
    assert (operation["subject_id"], operation["project_id"]) == (user["id"], project["id"])
    url = "/api/v1/operations/" + operation["id"]
    assert client.get("/api/v1/operations", headers=attack).json() == {"operations": []}
    assert client.get(url, headers=attack).status_code == 404
    assert client.get(url + "/logs/node-0", headers=attack).status_code == 404
    assert client.post(url + "/cancel", headers=attack, json={"node_ids": ids, "force": False}).status_code == 404
    assert not [value for _, value in remote.calls if value["action"] != "job.capabilities"]

    retained = ids[1::2]
    assign(client, project, retained, revision=1)
    for identity in ids:
        asyncio.run(service.jobs.reconcile(operation["id"], identity))
    saved = service.jobs.store.get(operation["id"])
    assert {value["node_id"] for value in saved["targets"] if value["state"] == "running"} == set(retained)
    assert {value["node_id"] for value in saved["targets"] if value["state"] == "failed"} == set(ids) - set(retained)
    assert {identity for identity, value in remote.calls if value["action"] == "job.submit"} == set(retained)

    service.auth.revoke(principal.id)
    token, _ = service.auth.issue("token", subject_id=user["id"], project_id=project["id"])
    fresh = {"Authorization": "Bearer " + token}
    assign(client, project, ids, revision=2)
    assert client.get(url, headers=fresh).json()["subject_id"] == user["id"]
    assert client.get(url, headers=attack).status_code == 404
    assert service.store.db.execute("SELECT subject_id,project_id FROM operations WHERE id=:p0",
                                    (operation["id"],)).fetchone() == (user["id"], project["id"])
    # The other project's unchanged resource grants still admit a new job on a denied target.
    control = request(1)
    preview = client.post("/api/v1/operation-previews", headers=attack, json=control)
    assert preview.status_code == 200 and preview.json()["targets"][0]["ready"]


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_terminal_ownership_is_private_within_a_shared_project(resource_console, count):
    client, service = resource_console
    service.store.save_node(node())
    user, project, _, headers = member(service, "Terminal owner")
    _, _, _, colleague = member(service, "Colleague", project)
    _, outside, _, other = member(service, "Other project")
    assign(client, project, ["node-0"])
    assign(client, outside, ["node-0"])
    retained = []
    for index in range(count):
        response = client.post("/api/v1/terminals", headers=headers, json={"node_id": "node-0", "label": f"Private {index}",
            "mode": "ephemeral", "cols": 80, "rows": 24, "confirm_execution": True,
            "idempotency_key": f"private-terminal-{index:04}"})
        assert response.status_code == 200, response.text
        value = response.json()
        retained.append(value["id"])
        url = "/api/v1/terminals/" + value["id"]
        for attack in (colleague, other):
            assert client.get(url, headers=attack).status_code == 404
            assert client.post(url + "/tickets", headers=attack).status_code == 404
            assert client.post(url + "/stop", headers=attack, json={"confirm_stop": True}).status_code == 404
        assert client.post(url + "/stop", headers=headers, json={"confirm_stop": True}).status_code == 200
    token, _ = service.auth.issue("token", subject_id=user["id"], project_id=project["id"])
    reopened = client.get("/api/v1/terminals", headers={"Authorization": "Bearer " + token}).json()["terminals"]
    assert {item["id"] for item in reopened} == set(retained)
    assert client.get("/api/v1/terminals", headers=colleague).json() == {"terminals": []}
    assert client.get("/api/v1/terminals", headers=other).json() == {"terminals": []}
