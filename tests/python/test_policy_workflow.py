# SPDX-License-Identifier: Apache-2.0
"""Exercise real runtime policy installation, role enforcement, revocation, and rollback."""

import pytest
from policy_fixtures import activate, install_pack
from test_identity_projects import member


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_runtime_policy_workflow_keeps_host_grants_and_recovers(policy_console, count):
    client, service, material = policy_console
    managed = install_pack(client, material)
    contribution = install_pack(client, material, "contribution")
    records = [member(service, f"Policy operator {index}", scopes=["workspaces:read", "workspaces:write"])
               for index in range(count)]
    for user, project, _, _ in records:
        response = client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}",
                              json={"roles": ["observer"], "revision": 0})
        assert response.status_code == 200, response.text
    first = activate(client, managed)
    for index, (user, project, actor, headers) in enumerate(records):
        assert client.get("/api/v1/workspaces", headers=headers).json() == {"workspaces": []}
        response = client.post("/api/v1/workspaces", headers=headers, json={"name": f"Policy workspace {index}"})
        assert response.status_code == 403 and response.json()["error"]["code"] == "policy_denied"
        assert client.get("/api/v1/policies", headers=headers).status_code == 403
        assert client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}", headers=headers,
                          json={"roles": ["operator"], "revision": 1}).status_code == 403
        preview = client.post("/api/v1/policy-preview", headers=headers, json={"requests": [
            {"action": "workspaces:write", "labels": {"local_owner": True, "roles": ["operator"]}}]})
        assert preview.status_code == 200, preview.text
        assert preview.json()["decisions"][0]["allowed"] is False
        assert preview.json()["decisions"][0]["host_allowed"] is True
        assert client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}",
                          json={"roles": ["operator"], "revision": 1}).status_code == 200
        made = client.post("/api/v1/workspaces", headers=headers, json={"name": f"Policy workspace {index}"})
        assert made.status_code == 201, made.text
        assert made.json()["name"] == f"Policy workspace {index}"
        limited, _ = service.auth.issue("token", subject_id=user["id"], project_id=project["id"], scopes=["workspaces:read"])
        assert client.post("/api/v1/workspaces", headers={"Authorization": "Bearer " + limited},
                           json={"name": "Forbidden ceiling extension"}).status_code == 403
        assert service.auth.current(actor.id).id == actor.id
    second = activate(client, contribution)
    assert second["revision"] > first["revision"] and second["previous"] == managed
    for _, _, _, headers in records:
        assert client.get("/api/v1/workspaces", headers=headers).status_code == 403
    rolled = activate(client, second["previous"])
    assert rolled["revision"] == second["revision"] + 1
    for index, (_, _, _, headers) in enumerate(records):
        assert [item["name"] for item in client.get("/api/v1/workspaces", headers=headers).json()["workspaces"]] == [f"Policy workspace {index}"]
    assert client.put("/api/v1/policy-publishers", json={"id": "example-publisher", "public_key": material["public_key"],
                                                       "enabled": False, "revision": 1}).status_code == 200
    for _, _, _, headers in records:
        assert client.get("/api/v1/workspaces", headers=headers).status_code == 503
    recovery = client.get("/api/v1/policies")
    assert recovery.status_code == 200 and recovery.json()["state"]["ready"] is False
    assert client.put("/api/v1/policy-publishers", json={"id": "example-publisher", "public_key": material["public_key"],
                                                       "enabled": True, "revision": 2}).status_code == 200
    activate(client, managed)
    for _, _, _, headers in records:
        assert client.get("/api/v1/workspaces", headers=headers).status_code == 200
    assert len(service.workspaces.all()) == count
