# SPDX-License-Identifier: Apache-2.0
"""Exercise package installation, scoped panels, concurrent saves and playback ownership."""

import pytest
from test_modules_packages import bundle, package


def installed(client, workspace_ids, capabilities):
    raw = bundle(*package(capabilities=capabilities))
    result = client.post("/api/v1/module-install-previews", content=raw,
                         headers={"Content-Type": "application/octet-stream"})
    assert result.status_code == 200, result.text
    preview = result.json()
    body = {"preview_id": preview["preview_id"], "digest": preview["digest"], "accept_unverified": True}
    result = client.post("/api/v1/modules", json=body)
    assert result.status_code == 201, result.text
    assert not result.json()["enabled"]
    result = client.post(f"/api/v1/modules/{preview['digest']}/activation", json={"enabled": True,
        "grants": [{"capability": name, "target_ids": workspace_ids} for name in capabilities]})
    assert result.status_code == 200, result.text
    return preview["digest"]


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_saved_workspaces_exact_grants_and_compare_and_swap(console, count):
    client, service = console
    spaces = [client.post("/api/v1/workspaces", json={"name": f"Workspace {i}"}).json() for i in range(count)]
    checksum = installed(client, [space["id"] for space in spaces], ["workspace:read", "workspace:write"])
    for index, space in enumerate(spaces):
        url = f"/api/v1/workspaces/{space['id']}"
        item = {"id": f"{index:032x}", "digest": checksum, "title": "Notes", "state": {}}
        result = client.put(url, json={"revision": 0, "name": space["name"], "instances": [item]})
        assert result.status_code == 200, result.text
        state_url = url + f"/instances/{item['id']}/state"
        result = client.put(state_url, json={"revision": 1, "state": {"notes": f"Text {index}"}})
        assert result.status_code == 200 and result.json()["revision"] == 2
        assert client.put(state_url, json={"revision": 1, "state": {"notes": "stale"}}).status_code == 409
        assert client.get(url).json()["instances"][0]["state"] == {"notes": f"Text {index}"}
    service.modules.revoke(checksum)
    assert client.put(state_url, json={"revision": 2, "state": {"notes": "revoked"}}).status_code == 403


def test_workspace_grant_and_identity_boundaries(console):
    client, _ = console
    spaces = [client.post("/api/v1/workspaces", json={"name": name}).json() for name in ("Granted", "Other")]
    checksum = installed(client, [spaces[0]["id"]], ["workspace:read"])
    item = {"id": "a" * 32, "digest": checksum, "title": "Clock", "state": {}}
    update = {"revision": 0, "name": "Changed", "instances": [item]}
    assert client.put(f"/api/v1/workspaces/{spaces[1]['id']}", json=update).status_code == 403
    assert client.put(f"/api/v1/workspaces/{spaces[0]['id']}", json=update).status_code == 200
    view_url = f"/api/v1/workspaces/{spaces[0]['id']}/views/" + "b" * 32
    assert client.put(view_url, json={"revision": 0, "layout": {"panels": {"a" * 32:
        {"id": "a" * 32, "contentComponent": "module", "params": None}}}}).status_code == 422
    assert client.put(view_url, json={"revision": 0, "layout": {"popoutGroups": [{}]}}).status_code == 422
    assert client.put(view_url, json={"revision": 0, "layout": {"__proto__": {}}}).status_code == 422


def test_audio_lease_revocation_and_conflicting_preferences(console):
    client, service = console
    space = client.post("/api/v1/workspaces", json={"name": "Audio"}).json()
    checksum = installed(client, [space["id"]], ["workspace:read", "audio:playback"])
    item = {"id": "a" * 32, "digest": checksum, "title": "Player", "state": {}}
    assert client.put(f"/api/v1/workspaces/{space['id']}", json={"revision": 0, "name": "Audio",
        "instances": [item]}).status_code == 200
    body = {"instance_id": item["id"], "surface_id": "b" * 32}
    result = client.post("/api/v1/audio/leases", json=body)
    assert result.status_code == 200
    lease = result.json()["id"]
    assert client.post("/api/v1/audio/leases", json={**body, "surface_id": "c" * 32}).status_code == 409
    url = f"/api/v1/audio/leases/{lease}"
    assert client.put(url, json={"surface_id": "c" * 32}).status_code == 409
    assert client.put(url, json={"surface_id": "b" * 32}).status_code == 200
    service.modules.revoke(checksum)
    assert client.put(url, json={"surface_id": "b" * 32}).status_code == 403
    assert lease not in service.audio.leases
    prefs = {"revision": 0, "volume": .25, "muted": True}
    assert client.put("/api/v1/audio/preferences", json=prefs).status_code == 200
    assert client.put("/api/v1/audio/preferences", json=prefs).status_code == 409


def test_delete_clears_views_and_tiles(console):
    client, _ = console
    space = client.post("/api/v1/workspaces", json={"name": "Temporary"}).json()
    view, surface, tile = "a" * 32, "b" * 32, "c" * 32
    assert client.put(f"/api/v1/workspaces/{space['id']}/views/{view}",
                      json={"revision": 0, "layout": {}}).status_code == 200
    assert client.put(f"/api/v1/workspace-surfaces/{surface}", json={"revision": 0, "layout": {},
        "tiles": [{"id": tile, "workspace_id": space["id"], "view_id": view}]}).status_code == 200
    assert client.delete(f"/api/v1/workspaces/{space['id']}?revision=0").status_code == 200
    saved = client.get(f"/api/v1/workspace-surfaces/{surface}").json()
    assert saved["tiles"] == [] and saved["revision"] == 2
