# SPDX-License-Identifier: Apache-2.0
"""Exercise real project ownership, credential ceilings and revocation through the API."""

import secrets

import pytest
from test_workspaces import installed

from ficc.errors import Failure
from ficc.identity_store import LOCAL_OWNER, LOCAL_PROJECT, PROJECT_SCOPES


def member(service, label, project=None, scopes=None):
    identities = service.auth.identities
    user = identities.create("user", label)
    project = project or identities.create("project", label + " project")
    identities.membership(project["id"], user["id"], sorted(PROJECT_SCOPES if scopes is None else scopes), 0)
    token, principal = service.auth.issue("token", label, subject_id=user["id"], project_id=project["id"])
    return user, project, principal, {"Authorization": "Bearer " + token}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distinct_projects_filter_lists_objects_views_and_surfaces(console, count):
    client, service = console
    outsider, outside, _, attack = member(service, "Outside")
    for index in range(count):
        user, project, principal, headers = member(service, f"Operator {index}")
        response = client.post("/api/v1/workspaces", headers=headers, json={"name": f"Private operations {index}"})
        assert response.status_code == 201, response.text
        space = response.json()
        url = f"/api/v1/workspaces/{space['id']}"
        assert [value["id"] for value in client.get("/api/v1/workspaces", headers=headers).json()["workspaces"]] == [space["id"]]
        assert client.get("/api/v1/workspaces", headers=attack).json() == {"workspaces": []}
        assert client.get(url, headers=attack).status_code == 404
        assert client.put(url, headers=attack, json={"name": "Cross-project edit", "revision": 0, "instances": []}).status_code == 404
        assert client.delete(url + "?revision=0", headers=attack).status_code == 404
        view, surface, tile = (secrets.token_hex(16) for _ in range(3))
        view_url = url + "/views/" + view
        layout = {"revision": 0, "layout": {"activeGroup": f"group-{index}"}}
        assert client.put(view_url, headers=headers, json=layout).status_code == 200
        assert client.get(view_url, headers=attack).status_code == 404
        assert client.put(view_url, headers=attack, json=layout).status_code == 404
        assert client.delete(view_url + "?revision=1", headers=attack).status_code == 404
        surface_url = "/api/v1/workspace-surfaces/" + surface
        body = {"revision": 0, "layout": {}, "tiles": [{"id": tile, "workspace_id": space["id"], "view_id": view}]}
        assert client.put(surface_url, headers=headers, json=body).status_code == 200
        assert client.get(surface_url, headers=attack).status_code == 404
        assert client.put(surface_url, headers=attack, json={**body, "revision": 1}).status_code == 404
        assert client.delete(surface_url + "?revision=1", headers=attack).status_code == 404
        assert client.put("/api/v1/workspace-surfaces/" + secrets.token_hex(16), headers=attack, json=body).status_code == 404
        # A second member can share the workspace, but cannot take its user's saved geometry.
        service.auth.identities.membership(project["id"], outsider["id"], sorted(PROJECT_SCOPES), 0)
        token, _ = service.auth.issue("token", subject_id=outsider["id"], project_id=project["id"])
        shared = {"Authorization": "Bearer " + token}
        assert client.get(url, headers=shared).json()["name"] == f"Private operations {index}"
        assert client.get(view_url, headers=shared).status_code == 404
        assert client.put(view_url, headers=shared, json=layout).status_code == 404
        assert client.get(surface_url, headers=shared).status_code == 404
        assert client.get("/api/v1/workspace-layouts", headers=shared).json() == {"surfaces": [], "unused_views": []}
        assert client.get("/api/v1/workspace-layouts", headers=attack).json() == {"surfaces": [], "unused_views": []}
        event = next(event for event in service.store.events() if event["action"] == "workspace.create" and event["target"] == space["id"])
        assert (event["actor"], event["subject_id"], event["project_id"]) == (principal.id, user["id"], project["id"])
    assert len(service.workspaces.all()) == count
    assert outside["id"] not in {service.store.db.execute("SELECT project_id FROM workspaces WHERE id=?", (space["id"],)).fetchone()[0]}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_members_cannot_gain_global_authority_or_self_administer(console, count):
    client, service = console
    records = [member(service, f"Workspace operator {i}", scopes=["workspaces:read", "workspaces:write"])
               for i in range(count)]
    for record in records:
        user, project, _, headers = record
        for path in ("nodes", "operations", "terminals", "agents", "audit", "tokens", "identities", "vm-profiles",
                     "module-targets", "modules/sandbox"):
            response = client.get("/api/v1/" + path, headers=headers)
            assert response.status_code == 403, (path, response.text)
        for path in ("identities", "projects"):
            assert client.post("/api/v1/" + path, headers=headers, json={"label": "Unauthorized"}).status_code == 403
        route = f"/api/v1/projects/{project['id']}/members/{user['id']}"
        assert client.put(route, headers=headers, json={"revision": 1, "scopes": ["identities:manage"]}).status_code == 403
        assert client.put(route, json={"revision": 1, "scopes": ["nodes:write"]}).status_code == 400
        with pytest.raises(Failure, match="exceeds"):
            service.auth.issue("token", scopes=["nodes:write"], subject_id=user["id"], project_id=project["id"])
        assert client.get("/api/v1/projects", headers=headers).json()["projects"] == [project]


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("change", ["membership", "user", "project"])
def test_authority_changes_preserve_unaffected_credentials(console, count, change):
    client, service = console
    identities = service.auth.identities
    affected = [member(service, f"Affected {i}") for i in range(count)]
    controls = [member(service, f"Unaffected {i}", scopes=sorted(PROJECT_SCOPES) if i % 2
                       else ["workspaces:read", "workspaces:write"]) for i in range(count)]
    for user, project, principal, headers in affected:
        if change == "membership":
            identities.membership(project["id"], user["id"], ["workspaces:read"], 1)
            assert client.post("/api/v1/workspaces", headers=headers, json={"name": "Denied"}).status_code == 403
            with pytest.raises(Failure):
                service.authorize(principal.id, "workspaces:write")
            assert client.get("/api/v1/workspaces", headers=headers).status_code == 200
            identities.membership(project["id"], user["id"], [], 2)
            assert identities.projects(user["id"]) == []
            assert client.get("/api/v1/session", headers=headers).status_code == 401
            identities.membership(project["id"], user["id"], sorted(PROJECT_SCOPES), 3)
        else:
            target = user if change == "user" else project
            result = identities.update(change, target["id"], target["label"], True, 0)
            assert result["revision"] == 1
            assert client.get("/api/v1/session", headers=headers).status_code == 401
            identities.update(change, target["id"], target["label"], False, 1)
            with pytest.raises(Failure, match="changed"):
                identities.update(change, target["id"], target["label"], True, 1)
        assert client.get("/api/v1/session", headers=headers).status_code == 401
        with pytest.raises(Failure):
            service.auth.current(principal.id)
    for user, project, principal, headers in controls:
        assert client.get("/api/v1/session", headers=headers).json()["principal"] == principal.public()
        service.authorize(principal.id, "workspaces:write")
        assert identities.projects(user["id"]) == [project]
    if change != "membership":
        with pytest.raises(Failure, match="recovery"):
            identities.update(change, LOCAL_OWNER if change == "user" else LOCAL_PROJECT, "Recovery", True, 0)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_bootstrap_preserves_identity_project_and_scope_ceiling(console, count):
    client, service = console
    _, _, _, control = member(service, "Unchanged")
    records = [member(service, f"Limited {i}") for i in range(count)]
    for index, record in enumerate(records):
        user, project, _, _ = record
        ceiling = ["modules:read", "workspaces:read"] if index % 2 else ["workspaces:read"]
        bootstrap, _ = service.auth.issue("bootstrap", scopes=ceiling, subject_id=user["id"], project_id=project["id"])
        response = client.post("/api/v1/session", json={"bootstrap": bootstrap})
        assert response.status_code == 200
        session = response.json()
        assert session["principal"]["subject_id"] == user["id"]
        assert session["principal"]["project_id"] == project["id"]
        assert session["principal"]["scopes"] == ceiling
        assert not session["principal"]["local_owner"]
        assert client.get("/api/v1/nodes").status_code == 403
        assert client.post("/api/v1/session", json={"bootstrap": bootstrap}).status_code == 401

        assert client.get("/api/v1/session", headers=control).status_code == 200


def test_project_switch_rotates_session_preserves_expiry_and_rejects_stale_tabs(console):
    client, service = console
    project = service.auth.identities.create("project", "Other")
    bootstrap, _ = service.auth.issue("bootstrap", scopes=["workspaces:read"])
    initial = client.post("/api/v1/session", json={"bootstrap": bootstrap}).json()
    old = service.auth.current(initial["principal"]["id"])
    headers = {"X-CSRF-Token": initial["csrf"], "X-FICC-Project": LOCAL_PROJECT}
    switched = client.post("/api/v1/session/project", headers=headers, json={"project_id": project["id"]})
    assert switched.status_code == 200
    changed = switched.json()
    fresh = service.auth.current(changed["principal"]["id"])
    assert fresh.expires_at == old.expires_at and fresh.scopes == old.scopes
    assert fresh.csrf != old.csrf and fresh.subject_id == old.subject_id
    with pytest.raises(Failure):
        service.auth.current(old.id)
    assert client.get("/api/v1/workspaces", headers={"X-FICC-Project": LOCAL_PROJECT}).status_code == 409
    assert client.post("/api/v1/workspaces", headers={"X-CSRF-Token": fresh.csrf, "X-FICC-Project": LOCAL_PROJECT},
                       json={"name": "Wrong tab"}).status_code == 409
    back = client.post("/api/v1/session/project", headers={"X-CSRF-Token": fresh.csrf}, json={"project_id": LOCAL_PROJECT})
    assert back.status_code == 200 and back.json()["principal"]["scopes"] == ["workspaces:read"]
    current = back.json()
    denied = client.post("/api/v1/session/project", headers={"X-CSRF-Token": current["csrf"]}, json={"project_id": "f" * 32})
    assert denied.status_code == 403
    assert client.get("/api/v1/session").json()["principal"]["id"] == current["principal"]["id"]


def test_module_grants_audio_and_invocation_are_project_bound(console):
    client, service = console
    user, project, principal, headers = member(service, "Workspace")
    _, _, _, other = member(service, "Unrelated")
    space = client.post("/api/v1/workspaces", headers=headers, json={"name": "Project audio"}).json()
    owner_space = client.post("/api/v1/workspaces", json={"name": "Local audio"}).json()
    targets = client.get("/api/v1/module-targets").json()["targets"]["workspace"]
    assert targets == [{"id": owner_space["id"], "name": "Local audio"}]
    selected, _ = service.auth.issue("token", project_id=project["id"])
    targets = client.get("/api/v1/module-targets", headers={"Authorization": "Bearer " + selected}).json()["targets"]["workspace"]
    assert targets == [{"id": space["id"], "name": "Project audio"}]
    checksum = installed(client, [space["id"], owner_space["id"]], ["workspace:read", "workspace:write", "audio:playback"])
    assert client.get("/api/v1/modules", headers=other).json() == {"modules": []}
    item = {"id": secrets.token_hex(16), "digest": checksum, "title": "Audio", "state": {}}
    url = "/api/v1/workspaces/" + space["id"]
    assert client.put(url, headers=headers, json={"revision": 0, "name": space["name"], "instances": [item]}).status_code == 200
    for module in client.get("/api/v1/modules", headers=headers).json()["modules"]:
        assert all(grant["target_ids"] == [space["id"]] for grant in module["grants"])
    assert client.post("/api/v1/module-invocations", headers=other, json={"workspace_id": space["id"],
        "instance_id": item["id"], "targets": [space["id"]], "action": "inspect"}).status_code == 404
    body = {"instance_id": item["id"], "surface_id": secrets.token_hex(16)}
    assert client.post("/api/v1/audio/leases", headers=other, json=body).status_code == 404
    lease = client.post("/api/v1/audio/leases", headers=headers, json=body)
    assert lease.status_code == 200
    prefs = {"revision": 0, "muted": True, "volume": .1}
    assert client.put("/api/v1/audio/preferences", headers=headers, json=prefs).status_code == 200
    assert client.get("/api/v1/audio/preferences", headers=other).json()["volume"] == .7
    service.auth.identities.membership(project["id"], user["id"], ["workspaces:read"], 1)
    with pytest.raises(Failure):
        service.audio.heartbeat(lease.json()["id"], principal.id, body["surface_id"])
    assert lease.json()["id"] not in service.audio.leases


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_new_surface_reserves_its_users_view_identity(console, count):
    client, service = console
    records = []
    for i in range(count):
        first = member(service, f"First {i}")
        records.append((first, member(service, f"Second {i}", first[1])))
    views = []
    for first, second in records:
        _, project, _, headers = first
        _, _, _, other = second
        space = client.post("/api/v1/workspaces", headers=headers, json={"name": "Shared"}).json()
        view, surface = secrets.token_hex(16), secrets.token_hex(16)
        result = client.put("/api/v1/workspace-surfaces/" + surface, headers=headers, json={"revision": 0, "layout": {},
            "tiles": [{"id": secrets.token_hex(16), "workspace_id": space["id"], "view_id": view}]})
        assert result.status_code == 200
        url = f"/api/v1/workspaces/{space['id']}/views/{view}"
        assert client.get(url, headers=headers).json()["revision"] == 0
        assert client.put(url, headers=other, json={"revision": 0, "layout": {}}).status_code == 404
        views.append((url, headers))
    for url, headers in views:
        assert client.get(url, headers=headers).json()["revision"] == 0


def test_queued_module_action_rechecks_project_package_grant(console, monkeypatch):
    client, service = console
    _, _, _, headers = member(service, "Module caller")
    space = client.post("/api/v1/workspaces", headers=headers, json={"name": "Module project"}).json()
    checksum = installed(client, [space["id"]], ["workspace:read"])
    item = {"id": secrets.token_hex(16), "digest": checksum, "title": "Local action", "state": {}}
    assert client.put(f"/api/v1/workspaces/{space['id']}", headers=headers,
                      json={"revision": 0, "name": space["name"], "instances": [item]}).status_code == 200
    called = []

    async def invoke(digest, action, targets, parameters, check, **kwargs):
        called.append(digest)
        with service.store.lock, service.store.db:
            service.store.db.execute("DELETE FROM module_grants WHERE digest=?", (digest,))
        check()
        pytest.fail("A module action continued after its workspace grant was removed")

    monkeypatch.setattr(service.module_runtime, "invoke", invoke)
    response = client.post("/api/v1/module-invocations", headers=headers, json={
        "workspace_id": space["id"], "instance_id": item["id"], "targets": [space["id"]], "action": "inspect"})
    assert called == [checksum] and response.status_code == 403
