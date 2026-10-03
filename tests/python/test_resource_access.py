# SPDX-License-Identifier: Apache-2.0
"""Verify project machine assignments, credential ceilings and current revocation."""

import pytest
from conftest import node
from resource_fixtures import assign
from resource_fixtures import resource_console as resource_console
from test_identity_projects import member


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_resource_assignment_and_revocation_filter_inventory(resource_console, count):
    client, service = resource_console
    ids = [f"node-{index}" for index in range(count)]
    for index in range(count):
        service.store.save_node(node(index))
    _, project, principal, headers = member(service, "Project operator")
    _, other, _, outside = member(service, "Other operator")
    assert client.get("/api/v1/nodes", headers=headers).json() == {"nodes": []}
    value = assign(client, project, ids)
    assign(client, other, ids)
    assert value["node_ids"] == sorted(ids) and value["revision"] == 1
    assert {item["id"] for item in client.get("/api/v1/nodes", headers=headers).json()["nodes"]} == set(ids)
    assert service.auth.current(principal.id).node_ids is None
    assert service.auth.current(principal.id).public()["node_ids"] == sorted(ids)
    assert client.get("/api/v1/project-resource-options", headers=headers).status_code == 403
    assert client.put(f"/api/v1/projects/{project['id']}/resources", headers=headers,
                      json={"node_ids": [], "root_ids": [], "revision": 1}).status_code == 403
    assert client.put(f"/api/v1/projects/{project['id']}/resources",
                      json={"node_ids": [], "root_ids": [], "revision": 0}).status_code == 409
    retained = ids[1::2]
    assign(client, project, retained, revision=1)
    assert {item["id"] for item in client.get("/api/v1/nodes", headers=headers).json()["nodes"]} == set(retained)
    for identity in ids:
        assert client.get("/api/v1/nodes/" + identity, headers=headers).status_code == (200 if identity in retained else 403)
        assert client.get("/api/v1/nodes/" + identity, headers=outside).status_code == 200


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_project_switch_preserves_raw_machine_ceilings(resource_console, count):
    client, service = resource_console
    for index in range(2):
        service.store.save_node(node(index))
    for index in range(count):
        user, first, _, _ = member(service, f"Switcher {index}", scopes=["nodes:read"])
        second = service.auth.identities.create("project", f"Second project {index}")
        service.auth.identities.membership(second["id"], user["id"], ["nodes:read"], 0)
        service.auth.resources.save(first["id"], ["node-0"], [], 0)
        service.auth.resources.save(second["id"], ["node-1"], [], 0)
        secret, principal = service.auth.issue("session", scopes=["nodes:read"],
                                             subject_id=user["id"], project_id=first["id"])
        client.cookies.clear()
        client.cookies.set("ficc_session", secret, domain="127.0.0.1", path="/")
        client.headers["X-CSRF-Token"] = principal.csrf
        assert client.get("/api/v1/permissions").json()["node_ids"] == ["node-0"]
        switched = client.post("/api/v1/session/project", json={"project_id": second["id"]})
        assert switched.status_code == 200
        assert switched.json()["principal"]["node_ids"] == ["node-1"]
        assert service.auth.current(switched.json()["principal"]["id"]).node_ids is None
        limited, initial = service.auth.issue("session", scopes=["nodes:read"], node_ids=["node-0"],
                                           subject_id=user["id"], project_id=first["id"])
        client.cookies.clear()
        client.cookies.set("ficc_session", limited, domain="127.0.0.1", path="/")
        client.headers["X-CSRF-Token"] = initial.csrf
        restricted = client.post("/api/v1/session/project", json={"project_id": second["id"]})
        assert restricted.status_code == 200 and restricted.json()["principal"]["node_ids"] == []
        assert service.auth.current(restricted.json()["principal"]["id"]).node_ids == ["node-0"]
        assert client.get("/api/v1/nodes").json() == {"nodes": []}
