# SPDX-License-Identifier: Apache-2.0
"""Exercise editor routes, session CSRF, typed requests and current grants."""

import secrets

from test_module_editor import install_editor


def test_editor_routes_require_csrf_and_current_bound_grants(console, tmp_path):
    client, service = console
    path = tmp_path / "api-files"
    path.mkdir()
    (path / "file.txt").write_text("Before\n")
    root = client.portal.call(service.files.register, str(path), "API text")
    workspace = service.workspaces.create("Editor")
    context, package, grants = install_editor(service, workspace, [root])
    base = "/api/v1/module-editor/"
    assert client.post(base + "roots", json=context, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    roots = client.post(base + "roots", json=context)
    assert roots.status_code == 200 and roots.json()["roots"][0]["id"] == root["id"]
    listing = client.post(base + "list", json={**context, "root_id": root["id"], "entry_id": roots.json()["roots"][0]["entry_id"]})
    assert listing.status_code == 200
    location = {"root_id": root["id"], "entry_id": listing.json()["entries"][0]["entry_id"]}
    read = client.post(base + "read", json={**context, "items": [location]})
    assert read.status_code == 200 and read.json()["results"][0]["data"]["text"] == "Before\n"
    assert client.post(base + "read", json={**context, "items": [location, location]}).status_code == 422
    key = secrets.token_hex(16)
    body = {**context, "accept_retained_exchange": True, "items": [{**location,
        "sha256": read.json()["results"][0]["data"]["sha256"], "text": "After\n"}]}
    assert client.post(base + "save", json={**body, "accept_retained_exchange": False}, headers={"Idempotency-Key": key}).status_code == 422
    result = client.post(base + "save", json=body, headers={"Idempotency-Key": key})
    assert result.status_code == 200 and result.json()["state"] == "succeeded", result.text
    assert (path / "file.txt").read_text() == "After\n"
    receipt = {**context, "operation_id": key}
    copy = client.post(base + "recovery", json={**receipt, "item_id": result.json()["items"][0]["id"], "copy": "original"})
    assert copy.status_code == 200 and copy.json()["text"] == "Before\n"
    service.modules.set_enabled(package, True, grants[:2])
    assert client.post(base + "cleanup", json={**receipt, "item_ids": [result.json()["items"][0]["id"]], "confirm": True}).status_code == 403
    assert client.post(base + "recovery", json={**receipt, "item_id": result.json()["items"][0]["id"], "copy": "draft"}).status_code == 200
    service.modules.set_enabled(package, False, [])
    assert client.post(base + "status", json=receipt).status_code == 403
    assert client.post(base + "read", json={**context, "items": [location]}).status_code == 403


def test_retained_edits_block_destructive_changes_but_allow_revocation(console, tmp_path):
    import copy

    import pytest

    from ficc.errors import Failure
    from ficc.module_editor_store import retained
    from ficc.store import Store

    client, service = console
    path = tmp_path / "retained-files"
    path.mkdir()
    (path / "file.txt").write_text("Before\n")
    root = client.portal.call(service.files.register, str(path), "Retained text")
    context, package, grants = install_editor(service, service.workspaces.create("Editor"), [root])
    base = "/api/v1/module-editor/"
    roots = client.post(base + "roots", json=context).json()
    listing = client.post(base + "list", json={**context, "root_id": root["id"], "entry_id": roots["roots"][0]["entry_id"]}).json()
    location = {"root_id": root["id"], "entry_id": listing["entries"][0]["entry_id"]}
    read = client.post(base + "read", json={**context, "items": [location]}).json()
    key = secrets.token_hex(16)
    result = client.post(base + "save", json={**context, "accept_retained_exchange": True, "items": [{**location,
        "sha256": read["results"][0]["data"]["sha256"], "text": "After\n"}]}, headers={"Idempotency-Key": key})
    assert result.status_code == 200 and result.json()["state"] == "succeeded"
    space = service.workspaces.get(context["workspace_id"])
    url = "/api/v1/workspaces/" + space["id"]
    with pytest.raises(Failure) as failed:
        service.files.unregister(root["id"])
    assert failed.value.code == "editor_retained" and failed.value.status == 409
    # A separately reopened store has no API editor instance or cached authority.
    reopened = Store(service.settings.state_dir / "state.sqlite3")
    try:
        assert retained(reopened, root_id=root["id"], digest=package)
    finally:
        reopened.close()
    assert client.delete(url, params={"revision": space["revision"]}).status_code == 409
    before = service.modules.get(package)
    assert client.delete("/api/v1/modules/" + package).status_code == 409
    assert service.modules.get(package) == before
    for change in ("remove", "digest", "targets"):
        items = copy.deepcopy(space["instances"])
        if change == "remove":
            items = []
        elif change == "digest":
            items[0]["digest"] = "f" * 64
        else:
            items[0]["targets"] = []
        response = client.put(url, json={"revision": space["revision"], "name": space["name"], "instances": items})
        assert response.status_code == 409 and response.json()["error"]["code"] == "editor_retained"
    rename = client.put(url, json={"revision": space["revision"], "name": "Renamed editor", "instances": space["instances"]})
    assert rename.status_code == 200
    disabled = client.post("/api/v1/modules/" + package + "/activation", json={"enabled": False, "grants": []})
    assert disabled.status_code == 200
    _, actor = service.auth.issue("token", scopes=["files:read"])
    service.auth.revoke(actor.id)
    service.modules.set_enabled(package, True, grants[:2])
    receipt = {**context, "operation_id": key}
    assert client.post(base + "recovery", json={**receipt, "item_id": result.json()["items"][0]["id"], "copy": "draft"}).status_code == 200
    service.modules.set_enabled(package, True, grants)
    cleaned = client.post(base + "cleanup", json={**receipt, "item_ids": [result.json()["items"][0]["id"]], "confirm": True})
    assert cleaned.status_code == 200 and not cleaned.json()["items"][0]["retained"]
    assert not retained(service.store, root_id=root["id"])
    assert client.post(base + "remove-receipt", json=receipt).status_code == 200
    assert service.files.unregister(root["id"]) == {"ok": True}
    assert client.delete(url, params={"revision": rename.json()["revision"]}).status_code == 200
    assert client.delete("/api/v1/modules/" + package).status_code == 200
