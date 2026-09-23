# SPDX-License-Identifier: Apache-2.0
"""Check credential boundaries and detecting denial paths."""

import time

import pytest
from conftest import node


def test_bootstrap_is_single_use_and_expires(console):
    client, service = console
    credential, _ = service.auth.issue("bootstrap", lifetime=60)
    first = client.post("/api/v1/session", json={"bootstrap": credential})
    assert first.status_code == 200
    assert "HttpOnly" in first.headers["set-cookie"]
    assert "SameSite=strict" in first.headers["set-cookie"]
    assert client.post("/api/v1/session", json={"bootstrap": credential}).status_code == 401
    stale, principal = service.auth.issue("bootstrap", lifetime=1)
    with service.store.db:
        service.store.db.execute("UPDATE credentials SET expires=? WHERE id=?", (time.time() - 1, principal.id))
    assert client.post("/api/v1/session", json={"bootstrap": stale}).status_code == 401
    with service.store.lock:
        values = service.store.db.execute("SELECT digest FROM credentials").fetchall()
    assert all(credential != row[0] for row in values)


@pytest.mark.parametrize("headers", [
    {"Host": "attacker.example"}, {"Host": "localhost:9999"},
    {"Origin": "https://attacker.example"}, {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site"},
])
def test_host_and_origin_guards(console, headers):
    client, _ = console
    response = client.get("/api/v1/nodes", headers=headers)
    assert response.status_code == 403
    assert "nodes" not in response.json()


def test_csrf_guard_detects_missing_or_wrong_secret(console):
    client, _ = console
    for csrf in ("", "wrong"):
        response = client.delete("/api/v1/session", headers={"X-CSRF-Token": csrf})
        assert response.status_code == 403
    assert client.get("/api/v1/session").status_code == 200
    assert client.delete("/api/v1/session").status_code == 200
    assert client.get("/api/v1/nodes").status_code == 401


@pytest.mark.parametrize("count", [1, 64])
def test_scoped_tokens_select_distinct_nodes_and_revoke(console, count):
    client, service = console
    for index in range(count):
        service.store.save_node(node(index))
    token, grant = service.auth.issue("token", "Observation", ["nodes:read", "resources:read"], ["node-0"])
    headers = {"Authorization": "Bearer " + token}
    response = client.get("/api/v1/nodes", headers=headers)
    assert [value["id"] for value in response.json()["nodes"]] == ["node-0"]
    denied_id = "node-1" if count == 64 else "not-in-grant"
    assert client.get(f"/api/v1/nodes/{denied_id}", headers=headers).status_code == 403
    assert client.get("/api/v1/tokens", headers=headers).status_code == 403
    assert client.delete("/api/v1/nodes/node-0", headers=headers).status_code == 403
    assert client.post("/api/v1/nodes/refresh", headers=headers,
                       json={"node_ids": ["node-0", denied_id]}).status_code == 403
    assert client.delete(f"/api/v1/tokens/{grant.id}").status_code == 200
    assert client.get("/api/v1/nodes", headers=headers).status_code == 401


def test_body_limit_and_safe_validation(console):
    client, _ = console
    response = client.post("/api/v1/node-previews", content=b"x" * (1048576 + 1))
    assert response.status_code == 413
    hostile = "private-local-value"
    response = client.post("/api/v1/node-previews", json={"profile": "-bad", "name": hostile})
    assert response.status_code == 422
    assert hostile not in response.text
    assert client.get("/api/v1/no-such-route").json()["error"]["code"] == "not_found"


def test_health_does_not_expose_inventory(console):
    client, _ = console
    client.cookies.clear()
    assert set(client.get("/api/v1/health").json()) == {"status", "version"}
    assert client.get("/api/v1/nodes").status_code == 401


def test_resource_grant_is_enforced_in_every_read_route(console):
    client, service = console
    from conftest import sample
    value = node()
    value["resources"] = sample()["resources"]
    service.store.save_node(value)
    token, _ = service.auth.issue("token", "Metadata", ["nodes:read"])
    headers = {"Authorization": "Bearer " + token}
    assert client.get("/api/v1/nodes", headers=headers).json()["nodes"][0]["resources"] is None
    assert client.get("/api/v1/nodes/node-0", headers=headers).json()["resources"] is None
    assert client.get("/api/v1/nodes/node-0/resources", headers=headers).status_code == 403
    token, _ = service.auth.issue("token", "Metrics", ["resources:read"])
    headers = {"Authorization": "Bearer " + token}
    assert client.get("/api/v1/nodes/node-0/resources", headers=headers).json()["resources"] is not None
    assert client.post("/api/v1/nodes/refresh", headers=headers,
                       json={"node_ids": ["node-0"]}).status_code == 403


def test_sensitive_audit_records_include_actor(console):
    client, service = console
    actor = client.get("/api/v1/session").json()["principal"]["id"]
    token, grant = service.auth.issue("token", "Example", ["nodes:read"])
    assert client.delete(f"/api/v1/tokens/{grant.id}").status_code == 200
    event = client.get("/api/v1/audit").json()["events"][0]
    assert event["actor"] == actor and event["target"] == grant.id
