# SPDX-License-Identifier: Apache-2.0
"""Keep resource-specific policy denials effective in lists and nested measurements."""

import json
import time

import pytest
from conftest import node, sample
from policy_fixtures import activate, install_pack, signed_pack
from resource_fixtures import assign
from test_identity_projects import member
from test_jobs import Remote
from test_jobs import request as job_request
from test_terminals import request as terminal_request

RULES = '''package ficc
import rego.v1
decisions := [decision(r) | some r in input.requests]
decision(r) := {"id":r.id,"allow":false,"reason":"hidden_measurements"} if {
  r.action == "resources:read"
} else := {"id":r.id,"allow":false,"reason":"hidden_target"} if {
  r.action in {"nodes:read", "jobs:read", "terminals:read"}
  r.authority.node_id != null
  not r.authority.node_id in data.visible_nodes
} else := {"id":r.id,"allow":false,"reason":"hidden_workspaces"} if {
  r.action == "workspaces:read"
} else := {"id":r.id,"allow":true,"reason":"permitted"}
'''


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_policy_filters_inventory_operations_terminals_and_catalogue(policy_console, tmp_path, monkeypatch, count):
    client, service, material = policy_console
    for index in range(count):
        value = node(index)
        value.update(resources=sample(index)["resources"], last_seen=time.time(), state="ready")
        service.store.save_node(value)
    user, project, actor, headers = member(service, "Collection reader")
    assign(client, project, [f"node-{index}" for index in range(count)])
    remote = Remote()
    monkeypatch.setattr(service.ssh, "job", remote.job)
    preview = client.post("/api/v1/operation-previews", headers=headers, json=job_request(count))
    assert preview.status_code == 200, preview.text
    submitted = client.post("/api/v1/operations", headers={**headers, "Idempotency-Key": "collection-filter-job"},
                            json={"preview_id": preview.json()["preview_id"]})
    assert submitted.status_code == 202, submitted.text
    operation = submitted.json()["id"]
    terminals = []
    for index in range(count):
        response = client.post("/api/v1/terminals", headers=headers,
                               json=terminal_request(index, idempotency_key=f"collection-terminal-{index:04}"))
        assert response.status_code == 200, response.text
        terminals.append(response.json())
        stopped = client.post("/api/v1/terminals/" + response.json()["id"] + "/stop", headers=headers,
                              json={"confirm_stop": True})
        assert stopped.status_code == 200 and stopped.json()["state"] == "stopped"
        assert client.get(f"/api/v1/nodes/node-{index}", headers=headers).json()["resources"]["cpu_count"] == index + 1
    assert len(client.get("/api/v1/operations/" + operation, headers=headers).json()["targets"]) == count
    assert len(client.get("/api/v1/terminals", headers=headers).json()["terminals"]) == count
    space = client.post("/api/v1/workspaces", json={"name": "Owner private catalogue entry"}).json()
    other = service.workspaces.scoped(actor).create("Other project catalogue entry")
    assert client.get("/api/v1/module-targets").json()["targets"]["workspace"] == [{"id": space["id"], "name": space["name"]}]
    assert other["id"] != space["id"]
    visible = [f"node-{index}" for index in range(count) if index % 2]
    archive = signed_pack(tmp_path / "filtered", material["key"], code=RULES.replace("data.visible_nodes", json.dumps(visible)))
    digest = install_pack(client, {**material, "managed": archive})
    activate(client, digest)
    listed = client.get("/api/v1/nodes", headers=headers)
    assert listed.status_code == 200, listed.text
    assert {value["id"] for value in listed.json()["nodes"]} == set(visible)
    assert all(value["resources"] is None for value in listed.json()["nodes"])
    for index in range(count):
        detail = client.get(f"/api/v1/nodes/node-{index}", headers=headers)
        assert detail.status_code == (200 if index % 2 else 403)
        if index % 2:
            assert detail.json()["resources"] is None
        assert client.get(f"/api/v1/nodes/node-{index}/resources", headers=headers).status_code == 403
        assert client.get("/api/v1/terminals/" + terminals[index]["id"], headers=headers).status_code == (200 if index % 2 else 403)
    rows = client.get("/api/v1/operations", headers=headers).json()["operations"]
    assert {target["node_id"] for row in rows for target in row["targets"]} == set(visible)
    detail = client.get("/api/v1/operations/" + operation, headers=headers)
    assert detail.status_code == (200 if visible else 404)
    if visible:
        assert detail.json()["request"]["node_ids"] == visible
    listed = client.get("/api/v1/terminals", headers=headers).json()["terminals"]
    assert {value["node_id"] for value in listed} == set(visible)
    assert client.get("/api/v1/workspaces").status_code == 403
    assert client.get("/api/v1/module-targets").json()["targets"]["workspace"] == []


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_member_preview_cannot_disable_active_enforcement(policy_console, count):
    client, service, material = policy_console
    user, project, _, headers = member(service, "Preview caller", scopes=["workspaces:read"])
    service.policies.records.bind(project["id"], user["id"], ["observer"], 0)
    activate(client, install_pack(client, material))
    original = service.policies.prepared
    asks = [{"action": "workspaces:read", "labels": {"distinct": index, "text": str(index) + "x" * 3940}}
            for index in range(count)]
    assert client.get("/api/v1/workspaces", headers=headers).status_code == 200
    response = client.post("/api/v1/policy-preview", headers=headers, json={"requests": asks})
    assert response.status_code == (200 if count == 1 else 400), response.text
    assert client.get("/api/v1/workspaces", headers=headers).status_code == 200
    small = client.post("/api/v1/policy-preview", headers=headers, json={"requests": [{"action": "workspaces:read"}]})
    assert small.status_code == 200 and small.json()["decisions"][0]["allowed"]
    assert service.policies.prepared is original and service.policies.status()["ready"]
    assert not service.policies.retired


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_label_dependent_invalid_result_only_stops_the_preview(policy_console, tmp_path, count):
    client, service, material = policy_console
    code = '''package ficc
import rego.v1
decisions := [decision(r) | some r in input.requests]
decision(r) := {"id":r.id,"allow":1,"reason":"invalid"} if { r.labels.invalid == true }
else := {"id":r.id,"allow":true,"reason":"permitted"}
'''
    archive = signed_pack(tmp_path / "label-dependent", material["key"], code=code)
    activate(client, install_pack(client, {**material, "managed": archive}))
    _, _, _, headers = member(service, "Label preview", scopes=["workspaces:read"])
    original = service.policies.prepared
    assert client.get("/api/v1/workspaces", headers=headers).status_code == 200
    asks = [{"action": "workspaces:read", "labels": {"index": index, "invalid": index == count - 1}}
            for index in range(count)]
    assert client.post("/api/v1/policy-preview", headers=headers, json={"requests": asks}).status_code == 503
    assert client.get("/api/v1/workspaces", headers=headers).status_code == 200
    assert service.policies.prepared is original and service.policies.status()["ready"]
    assert not service.policies.retired
