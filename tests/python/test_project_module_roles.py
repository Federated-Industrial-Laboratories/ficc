# SPDX-License-Identifier: Apache-2.0
"""Exercise installed administration and container panels under real project policy."""

import secrets

import pytest
from policy_fixtures import activate, install_pack
from project_module_fixtures import checked, installed
from resource_fixtures import assign
from test_identity_projects import member
from test_module_admin_routes import fixture as admin_fixture
from test_module_containers_routes import fixture as container_fixture

from ficc.identity_store import LOCAL_PROJECT, PROJECT_SCOPES


@pytest.mark.parametrize("kind,fixture,name,role", [
    ("admin", admin_fixture, "system-admin", "system-operator"),
    ("containers", container_fixture, "containers", "container-operator"),
])
def test_project_lifecycle_panel_uses_installed_role_and_durable_receipt(policy_console, tmp_path, monkeypatch,
                                                                     kind, fixture, name, role):
    client, service, material = policy_console
    context, _preview, profile, provider, _old_digest, _grants = fixture((client, service), tmp_path, monkeypatch, 1)
    workspace = service.workspaces.get(context["workspace_id"])
    node = profile["node_id"]
    digest, _grants = installed(client, [workspace["id"]], [node], name)
    panel = {"id": context["instance_id"], "digest": digest, "title": name, "targets": [node]}
    checked(client.put(f"/api/v1/workspaces/{workspace['id']}", json={"revision": workspace["revision"],
                                                                  "name": workspace["name"], "instances": [panel]}))
    project = service.auth.identities.project(LOCAL_PROJECT)
    assign(client, project, [node])
    user, _, _actor, headers = member(service, "Panel operator", project, scopes=sorted(PROJECT_SCOPES))
    outsider, outside, _, foreign = member(service, "Other project", scopes=sorted(PROJECT_SCOPES))
    assign(client, outside, [node])
    for who, space in ((user, project), (outsider, outside)):
        checked(client.put(f"/api/v1/projects/{space['id']}/policy-roles/{who['id']}",
                           json={"roles": [role], "revision": 0}))
    activate(client, install_pack(client, material))
    request = {**context, "targets": [node], "action": "load"}
    result = checked(client.post("/api/v1/module-invocations", headers=headers, json=request))
    data = result["results"][0]["data"]
    assert not data["notice"] and len(data["rows"]) == 1
    identity = data["rows"][0]["id"]
    preview = checked(client.post("/api/v1/module-invocations", headers=headers, json={**request,
        "action": "preview-start", "parameters": {"resource_ids": [identity]}}))["results"][0]["data"]
    base = f"/api/v1/module-{kind}/"
    operation = checked(client.post(base + "commit", headers={**headers, "Idempotency-Key": secrets.token_hex(16)},
        json={**context, "preview_id": preview["preview_id"], "confirm": True}))
    body = {**context, "operation_id": operation["id"]}
    assert client.post(base + "operation", headers=foreign, json=body).status_code == 404
    operation = checked(client.post(base + "operation", headers=headers, json=body))
    assert operation["targets"][0]["state"] == "observed" and len(provider.calls) == 1
    assert checked(client.post(base + "history", headers=headers, json=context))["operations"][0]["id"] == operation["id"]
    checked(client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}",
                       json={"roles": ["observer"], "revision": 1}))
    assert client.post(base + "history", headers=headers, json=context).status_code == 403
    host = service.administration if kind == "admin" else service.containers
    assert host.records.get(operation["id"])["targets"][0]["state"] == "observed"


def test_system_status_panel_maps_to_resource_scope(policy_console):
    from conftest import node

    client, service, material = policy_console
    system = {**node(), "id": "a" * 32}
    service.store.save_node(system)
    user, project, actor, headers = member(service, "Status operator", scopes=[
        "nodes:read", "resources:read", "workspaces:read", "workspaces:write", "modules:read", "modules:execute"])
    assign(client, project, [system["id"]])
    space = checked(client.post("/api/v1/workspaces", headers=headers, json={"name": "System status"}), 201)
    digest, _grants = installed(client, [space["id"]], [system["id"]], "system-status")
    identity = secrets.token_hex(16)
    checked(client.put(f"/api/v1/workspaces/{space['id']}", headers=headers, json={"revision": 0, "name": space["name"],
        "instances": [{"id": identity, "digest": digest, "title": "Status", "targets": [system["id"]]}]}))
    checked(client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}",
                       json={"roles": ["system-operator"], "revision": 0}))
    activate(client, install_pack(client, material))
    body = {"workspace_id": space["id"], "instance_id": identity, "targets": [system["id"]], "action": "load"}
    result = checked(client.post("/api/v1/module-invocations", headers=headers, json=body))
    assert result["results"][0]["data"]["rows"][0]["id"] == system["id"]
    checked(client.put(f"/api/v1/projects/{project['id']}/members/{user['id']}",
        json={"revision": 1, "scopes": [scope for scope in actor.scopes if scope != "resources:read"]}))
    assert client.post("/api/v1/module-invocations", headers=headers, json=body).status_code == 403
