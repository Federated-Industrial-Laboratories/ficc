# SPDX-License-Identifier: Apache-2.0
"""Keep shared recipes project-scoped and strip panel data and private geometry."""

import json

from test_identity_projects import member


def test_template_versions_share_only_clean_panel_recipes(console):
    client, service = console
    _user, project, principal, first = member(service, "Template author")
    _user2, _project2, _principal2, same = member(service, "Project colleague", project=project)
    _outsider, _other, _outside, other = member(service, "Different project")
    workspace = service.workspaces.scoped(principal).create("Operations")
    # Existing saved module state must never enter the shared recipe.
    workspace["instances"] = [{"id": "a" * 32, "digest": "b" * 64, "title": "Notes",
                                "state": {"text": "private scratch text"}, "targets": ["c" * 32]}]
    with service.store.lock, service.store.db:
        service.store.db.execute("UPDATE workspaces SET value=:p0 WHERE id=:p1", (json.dumps(workspace), workspace["id"]))
    body = {"workspace_id": workspace["id"], "revision": 0, "name": "Team console"}
    assert client.post("/api/v1/workspace-templates", headers=other, json=body).status_code == 404
    first_version = client.post("/api/v1/workspace-templates", headers=first, json=body)
    assert first_version.status_code == 201, first_version.text
    first_version = first_version.json()
    assert first_version["panels"] == [{"digest": "b" * 64, "title": "Notes"}]
    second_version = client.post("/api/v1/workspace-templates", headers=first, json=body).json()
    assert second_version["version"] == 2 and second_version["id"] != first_version["id"]
    shared = client.get("/api/v1/workspace-templates", headers=same)
    assert shared.json()["templates"] == [first_version, second_version]
    assert "private scratch text" not in shared.text and "c" * 32 not in shared.text
    assert client.get("/api/v1/workspace-templates", headers=other).json() == {"templates": []}
    path = "/api/v1/workspace-templates/" + first_version["id"]
    assert client.delete(path, headers=other).status_code == 404
    assert client.delete(path, headers=same).status_code == 200
    assert service.workspaces.scoped(principal).get(workspace["id"])["instances"][0]["state"] == {"text": "private scratch text"}
