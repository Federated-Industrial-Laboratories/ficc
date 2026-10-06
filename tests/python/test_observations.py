# SPDX-License-Identifier: Apache-2.0
"""Protect explicit observation disclosure, current authority, and projection privacy."""

import json
import sqlite3
import time

import pytest
from conftest import node, sample
from fastapi import Request
from policy_fixtures import activate, install_pack, signed_pack
from test_identity_projects import member
from test_jobs import request as job_request

from ficc.errors import Failure
from ficc.observation_routes import restrict_request

BASE = "/api/v1/observations/nodes"
SCOPES = ["observations:read", "observations:resources"]


def token(service, scopes=SCOPES, nodes=None, **kwargs):
    secret, actor = service.auth.issue("token", scopes=scopes, node_ids=nodes, **kwargs)
    return {"Authorization": "Bearer " + secret}, actor


def test_disclosure_permission_is_explicit_and_inventory_has_no_resources(console):
    client, service = console
    service.store.save_node(node())
    headers, _ = token(service, ["nodes:read", "resources:read"])
    assert client.get(BASE, headers=headers).status_code == 403
    assert client.get(BASE + "/node-0/resources", headers=headers).status_code == 403
    assert client.get("/api/v1/nodes", headers=headers).status_code == 200
    headers, _ = token(service, ["observations:read"])
    listed = client.get(BASE, headers=headers)
    assert listed.status_code == 200
    assert listed.json() == {"nodes": [{"id": "node-0", "name": "Machine 0", "state": "unconfigured",
                                        "last_seen": None, "sample_age_seconds": None, "stale": True}]}
    assert client.get(BASE + "/node-0/resources", headers=headers).status_code == 403
    headers, _ = token(service, ["observations:resources"])
    assert client.get(BASE + "/node-0/resources", headers=headers).status_code == 403


def test_inventory_intersects_project_credential_and_target_policy(console, monkeypatch):
    client, service = console
    for index in range(4):
        service.store.save_node(node(index))
    user, project, _, _ = member(service, "Observation user", scopes=SCOPES)
    service.auth.resources.save(project["id"], ["node-0", "node-1", "node-2"], [], 0)
    checked = []

    def policy(actor, scope, node_id, root_id):
        checked.append((scope, node_id))
        if scope == "observations:read" and node_id == "node-1":
            raise Failure("policy_denied", "Not approved for disclosure.", 403)
        if scope == "observations:resources" and node_id == "node-0":
            raise Failure("policy_denied", "Measurements are not approved for disclosure.", 403)

    monkeypatch.setattr(service.auth, "policy_check", policy)
    headers, actor = token(service, nodes=["node-0", "node-1", "node-3"],
                           subject_id=user["id"], project_id=project["id"])
    listed = client.get(BASE, headers=headers)
    assert listed.status_code == 200
    assert [row["id"] for row in listed.json()["nodes"]] == ["node-0"]
    assert ("observations:read", "node-0") in checked and ("observations:read", "node-1") in checked
    assert client.get(BASE + "/node-0/resources", headers=headers).status_code == 403
    assert ("observations:resources", "node-0") in checked
    for identity in ("node-1", "node-2", "node-3"):
        assert client.get(BASE + f"/{identity}/resources", headers=headers).status_code == 403
    records = [event for event in service.store.events() if event["actor"] == actor.id]
    assert records and all((event["subject_id"], event["project_id"]) ==
                           (user["id"], project["id"]) for event in records)
    assert any(event["target"] == "node-0" and event["outcome"] == "allowed" for event in records)
    assert any(event["target"] == "node-1" and event["outcome"] == "denied" for event in records)
    assert "Machine" not in json.dumps(records) and "Bearer" not in json.dumps(records)


def test_current_membership_assignments_expiry_and_revocation(console):
    client, service = console
    service.store.save_node(node())
    user, project, _, _ = member(service, "Observation user", scopes=SCOPES)
    service.auth.resources.save(project["id"], ["node-0"], [], 0)
    headers, actor = token(service, subject_id=user["id"], project_id=project["id"])
    path = BASE + "/node-0/resources"
    assert client.get(path, headers=headers).status_code == 200
    service.auth.identities.membership(project["id"], user["id"], ["observations:read"], 1)
    assert client.get(path, headers=headers).status_code == 403
    service.auth.identities.membership(project["id"], user["id"], SCOPES, 2)
    assert client.get(path, headers=headers).status_code == 200
    service.auth.resources.save(project["id"], [], [], 1)
    assert client.get(BASE, headers=headers).json() == {"nodes": []}
    assert client.get(path, headers=headers).status_code == 403
    service.auth.resources.save(project["id"], ["node-0"], [], 2)
    with service.store.lock, service.store.db:
        service.store.db.execute("UPDATE credentials SET expires=:p0 WHERE id=:p1", (time.time() - 1, actor.id))
    assert client.get(path, headers=headers).status_code == 401
    fresh, actor = token(service, subject_id=user["id"], project_id=project["id"])
    assert client.get(path, headers=fresh).status_code == 200
    service.auth.revoke(actor.id)
    assert client.get(path, headers=fresh).status_code == 401


def test_new_membership_scope_does_not_broaden_existing_token(console):
    client, service = console
    user, project, _, headers = member(service, "Existing observer", scopes=["nodes:read", "resources:read"])
    service.auth.identities.membership(project["id"], user["id"], SCOPES, 1)
    assert client.get(BASE, headers=headers).status_code == 403
    fresh, _ = token(service, subject_id=user["id"], project_id=project["id"])
    assert client.get(BASE, headers=fresh).status_code == 200


def test_membership_attenuation_cannot_hide_a_broad_credential_ceiling(console):
    client, service = console
    user, project, _, headers = member(service, "Broad observer", scopes=[*SCOPES, "nodes:read"])
    service.auth.identities.membership(project["id"], user["id"], SCOPES, 1)
    result = client.get(BASE, headers=headers)
    assert result.status_code == 403 and result.json()["error"]["code"] == "observation_credential"


def test_cached_sample_preserves_null_and_stale_and_excludes_private_state(console):
    client, service = console
    value = node()
    value.update(last_seen=time.time() - 8000, resources=sample()["resources"], state="ready",
                 error={"message": "PRIVATE-ERROR"})
    value["resources"]["cpu_percent"] = None
    service.store.save_node(value)
    headers, _ = token(service)
    result = client.get(BASE + "/node-0/resources", headers=headers)
    assert result.status_code == 200
    payload = result.json()
    assert set(payload) == {"node_id", "resources", "last_seen", "sample_age_seconds", "stale"}
    assert payload["resources"] == value["resources"]
    assert payload["stale"] is True and payload["sample_age_seconds"] >= 8000
    assert payload["last_seen"] == value["last_seen"]
    inventory = client.get(BASE, headers=headers).json()["nodes"][0]
    assert inventory["state"] == "degraded" and "resources" not in inventory
    assert all(secret not in json.dumps(payload) + json.dumps(inventory)
               for secret in ("PRIVATE-ERROR", "operator", "synthetic-key", "machine-0.example", "lab-0", "dGVzdA=="))
    service.store.save_node(node())
    assert client.get(BASE + "/node-0/resources", headers=headers).json() == {
        "node_id": "node-0", "resources": None, "last_seen": None, "sample_age_seconds": None, "stale": True}


def test_audit_failure_and_unknown_resource_fields_prevent_disclosure(console, monkeypatch):
    client, service = console
    value = node()
    value["resources"] = {**sample()["resources"], "private": "SECRET-SAMPLE"}
    service.store.save_node(value)
    headers, _ = token(service)
    result = client.get(BASE + "/node-0/resources", headers=headers)
    assert result.status_code == 503 and "SECRET-SAMPLE" not in result.text
    service.store.save_node(node())

    def failed(*args, **kwargs):
        raise sqlite3.OperationalError("SECRET-STORAGE")

    monkeypatch.setattr(service.store, "audit", failed)
    for path in (BASE, BASE + "/node-0/resources", "/api/v1/projects"):
        result = client.get(path, headers=headers)
        assert result.status_code == 503 and result.json()["error"]["code"] == "audit_unavailable"
        assert "SECRET-STORAGE" not in result.text and "Machine" not in result.text


def test_observation_routes_cannot_refresh_or_mutate(console, monkeypatch):
    client, service = console
    service.store.save_node(node())
    headers, _ = token(service)

    async def forbidden(*args, **kwargs):
        pytest.fail("Observation attempted a remote operation.")

    monkeypatch.setattr(service, "refresh", forbidden)
    monkeypatch.setattr(service.ssh, "probe", forbidden)
    before = service.store.node("node-0")
    assert client.get(BASE + "/node-0/resources", headers=headers).status_code == 200
    assert client.get(BASE, headers=headers).status_code == 200
    for method in (client.post, client.put, client.delete):
        assert method(BASE, headers=headers).status_code == 405
        assert method(BASE + "/node-0/resources", headers=headers).status_code == 405
    assert service.store.node("node-0") == before


def test_observation_credential_cannot_access_general_endpoints_or_accept_broader_tokens(console):
    client, service = console
    service.store.save_node(node())
    headers, _ = token(service)
    for path in ("/api/v1/nodes", "/api/v1/nodes/node-0/resources", "/api/v1/operations",
                 "/api/v1/operations/unknown/logs/node-0", "/api/v1/agents"):
        assert client.get(path, headers=headers).status_code == 403, path
    assert client.get("/api/v1/file-roots", headers=headers).status_code == 403
    assert client.post("/api/v1/files/list", headers=headers,
                       json={"root_id": "a" * 32, "entry_id": "entry"}).status_code == 403
    assert client.post("/api/v1/nodes/refresh", headers=headers, json={"node_ids": ["node-0"]}).status_code == 403
    assert client.post("/api/v1/operation-previews", headers=headers, json=job_request()).status_code == 403
    for path in (BASE, BASE + "/node-0/resources"):
        assert client.get(path).status_code == 403
        broad, _ = token(service, [*SCOPES, "nodes:read"])
        result = client.get(path, headers=broad)
        assert result.status_code == 403 and result.json()["error"]["code"] == "observation_credential"


def test_observation_token_cannot_read_other_project_or_general_metadata(console):
    client, service = console
    user, project, actor, headers = member(service, "Observation member", scopes=SCOPES)
    other = service.auth.identities.create("project", "UNDISCLOSED-PROJECT")
    service.auth.identities.membership(other["id"], user["id"], ["nodes:read"], 0)
    assert client.get(BASE, headers=headers).json() == {"nodes": []}
    # The original observation ceiling still restricts the token after membership narrows.
    service.auth.identities.membership(project["id"], user["id"], ["observations:read"], 1)
    for path in ("/api/v1/projects", "/api/v1/session", "/api/v1/permissions", "/api/v1/policy-status"):
        result = client.get(path + "?private=DO-NOT-RECORD", headers=headers)
        assert result.status_code == 403
        assert result.json()["error"]["code"] == "observation_boundary"
        assert other["id"] not in result.text and other["label"] not in result.text
    events = [event for event in service.store.events() if event["action"] == "observation.request"]
    assert len(events) == 4
    assert all((event["actor"], event["subject_id"], event["project_id"], event["target"], event["outcome"]) ==
               (actor.id, user["id"], project["id"], "unsupported_request", "denied") for event in events)
    assert "DO-NOT-RECORD" not in json.dumps(events)
    assert client.get("/api/v1/projects").status_code == 200
    broad, _ = token(service, [*SCOPES, "nodes:read"])
    assert client.get("/api/v1/session", headers=broad).status_code == 200


@pytest.mark.parametrize("method,path", [
    ("HEAD", BASE), ("POST", BASE), ("DELETE", BASE + "/node-0/resources"),
    ("GET", BASE + "/"), ("GET", BASE + "/node-0/resources/"),
    ("GET", BASE + "/node-0/resources/private"), ("GET", BASE + "-extra"),
    ("GET", "/private" + BASE), ("GET", BASE + "/node-0/other/resources"),
])
def test_shared_observation_boundary_has_exact_method_and_path_allowlist(console, method, path):
    _, service = console
    _, actor = token(service)
    request = Request({"type": "http", "method": method, "path": path,
                       "query_string": b"private=DO-NOT-RECORD", "headers": []})
    with pytest.raises(Failure) as denied:
        restrict_request(request, actor, service.store)
    assert denied.value.status == 403 and denied.value.code == "observation_boundary"
    event = service.store.events()[0]
    assert event["target"] == "unsupported_request" and event["actor"] == actor.id
    assert path not in json.dumps(event) and "DO-NOT-RECORD" not in json.dumps(event)


def test_active_policy_role_and_target_filter(policy_console, tmp_path):
    client, service, material = policy_console
    for index in range(2):
        service.store.save_node(node(index))
    user, project, _, headers = member(service, "Agent observer", scopes=SCOPES)
    service.auth.resources.save(project["id"], ["node-0", "node-1"], [], 0)
    service.policies.records.bind(project["id"], user["id"], ["observer"], 0)
    activate(client, install_pack(client, material))
    assert client.get(BASE, headers=headers).status_code == 403
    service.policies.records.bind(project["id"], user["id"], ["agent-observer"], 1)
    assert len(client.get(BASE, headers=headers).json()["nodes"]) == 2
    assert client.get(BASE + "/node-0/resources", headers=headers).status_code == 200
    rules = '''package ficc
import rego.v1
decisions := [decision(r) | some r in input.requests]
decision(r) := {"id": r.id, "allow": false, "reason": "private_target"} if {
  r.action == "observations:read"
  r.authority.node_id == "node-1"
} else := {"id": r.id, "allow": true, "reason": "permitted"}
'''
    archive = signed_pack(tmp_path / "filtered-observations", material["key"], code=rules)
    activate(client, install_pack(client, {**material, "managed": archive}))
    assert [item["id"] for item in client.get(BASE, headers=headers).json()["nodes"]] == ["node-0"]
    assert client.get(BASE + "/node-1/resources", headers=headers).status_code == 403
