# SPDX-License-Identifier: Apache-2.0
"""Check removal, revision conflicts and reuse of bounded layout capacity."""

import pytest


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_remove_saved_window_then_unreferenced_views(console, count):
    client, _ = console
    space = client.post("/api/v1/workspaces", json={"name": "Retained data"}).json()
    pairs = [(f"{index + 1:032x}", f"{index + 100:032x}") for index in range(count)]
    for view, surface in pairs:
        assert client.put(f"/api/v1/workspaces/{space['id']}/views/{view}",
            json={"revision": 0, "layout": {}}).status_code == 200
        assert client.put(f"/api/v1/workspace-surfaces/{surface}", json={"revision": 0, "layout": {},
            "tiles": [{"id": view, "workspace_id": space["id"], "view_id": view}]}).status_code == 200
    saved = client.get("/api/v1/workspace-layouts").json()
    assert len(saved["surfaces"]) == count and not saved["unused_views"]
    for view, surface in pairs:
        url = f"/api/v1/workspaces/{space['id']}/views/{view}?revision=1"
        assert client.delete(url).status_code == 409
        assert client.delete(f"/api/v1/workspace-surfaces/{surface}?revision=0").status_code == 409
        assert client.delete(f"/api/v1/workspace-surfaces/{surface}?revision=1").status_code == 200
        assert client.delete(url).status_code == 200
    assert client.get("/api/v1/workspace-layouts").json() == {"surfaces": [], "unused_views": []}
    assert client.get(f"/api/v1/workspaces/{space['id']}").json() == space
    assert client.put(f"/api/v1/workspace-surfaces/{'f' * 32}",
        json={"revision": 0, "layout": {}, "tiles": []}).status_code == 200


def test_panel_removal_invalidates_only_affected_views_and_blocks_stale_save(console):
    from test_workspaces import installed

    client, _ = console
    space = client.post("/api/v1/workspaces", json={"name": "Panels"}).json()
    checksum = installed(client, [space["id"]], ["workspace:read"])
    items = [{"id": key * 32, "digest": checksum, "title": key, "state": {"notes": key}} for key in ("a", "b")]
    url = f"/api/v1/workspaces/{space['id']}"
    assert client.put(url, json={"name": "Panels", "revision": 0, "instances": items}).status_code == 200
    for key in ("a", "b"):
        assert client.put(url + f"/views/{key * 32}", json={"revision": 0, "layout": {"panels": {
            key * 32: {"id": key * 32, "contentComponent": "module", "params": {"instanceId": key * 32}}}}}).status_code == 200
    assert client.put(url, json={"name": "Panels", "revision": 1, "instances": items[1:]}).status_code == 200
    removed = client.get(url + f"/views/{'a' * 32}").json()
    retained = client.get(url + f"/views/{'b' * 32}").json()
    assert removed["revision"] == 2 and removed["layout"] == {}
    assert retained["revision"] == 1 and list(retained["layout"]["panels"]) == ["b" * 32]
    assert client.put(url + f"/views/{'a' * 32}", json={"revision": 1, "layout": {}}).status_code == 409
    assert client.get(url).json()["instances"][0]["state"] == {"notes": "b"}
