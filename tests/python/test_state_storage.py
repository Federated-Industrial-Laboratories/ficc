# SPDX-License-Identifier: Apache-2.0
"""Run matching controller, transaction and recovery workflows on both state backends."""

import json
import secrets
from contextlib import closing

import pytest
from fastapi.testclient import TestClient
from test_identity_projects import member
from test_workspaces import installed

from ficc.api import create_app
from ficc.auth import Auth
from ficc.backup import export, restore
from ficc.backup_database import SCHEMA, connect
from ficc.errors import Failure
from ficc.identity_store import LOCAL_OWNER
from ficc.service import Service
from ficc.settings import Settings
from ficc.state_provider import StorageFailure
from ficc.store import Store


def settings(path):
    return Settings(state_dir=path, control=False, poll_interval=3600, stale_after=7200)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_network_and_local_project_roundtrip_and_portable_recovery(storage_state, tmp_path, count):
    app = create_app(settings(storage_state))
    saved = []
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        service = app.state.service
        owner, _ = service.auth.issue("token")
        client.headers.update({"Authorization": "Bearer " + owner})
        records = [member(service, f"Owner {index}") for index in range(count)]
        spaces = [client.post("/api/v1/workspaces", headers=headers, json={"name": f"Project notes {index}"}).json()
                  for index, (_, _, _, headers) in enumerate(records)]
        checksum = installed(client, [space["id"] for space in spaces], ["workspace:read", "workspace:write", "audio:playback"])
        for index, ((user, project, _, headers), space) in enumerate(zip(records, spaces, strict=True)):
            panel, view, surface, tile = (secrets.token_hex(16) for _ in range(4))
            result = client.put(f"/api/v1/workspaces/{space['id']}", headers=headers, json={
                "name": space["name"], "revision": 0, "instances": [{"id": panel, "digest": checksum,
                "title": f"Notes {index}", "state": {"notes": f"Private project content {index}"}}]})
            assert result.status_code == 200, result.text
            view_value = client.put(f"/api/v1/workspaces/{space['id']}/views/{view}", headers=headers,
                                    json={"revision": 0, "layout": {"activeGroup": f"group-{index}"}}).json()
            surface_value = client.put(f"/api/v1/workspace-surfaces/{surface}", headers=headers, json={
                "revision": 0, "layout": {}, "tiles": [{"id": tile, "workspace_id": space["id"], "view_id": view}]}).json()
            assert view_value["revision"] == surface_value["revision"] == 1
            preferences = client.put("/api/v1/audio/preferences", headers=headers,
                                     json={"revision": 0, "volume": (index + 1) / 100, "muted": bool(index % 2)}).json()
            assert preferences["revision"] == 1
            saved.append((user, project, headers, result.json(), view_value, surface_value, preferences))
        if count > 1:
            for index, record in enumerate(saved):
                other = saved[(index + 1) % count][2]
                assert client.get(f"/api/v1/workspaces/{record[3]['id']}", headers=other).status_code == 404
        assert client.get("/api/v1/workspaces").json()["workspaces"] == []
    reopened = Service(settings(storage_state))
    try:
        for user, project, headers, workspace, view, surface, preferences in saved:
            principal = reopened.auth.resolve(headers["Authorization"][7:])
            scoped = reopened.workspaces.scoped(principal)
            assert scoped.get(workspace["id"]) == workspace
            assert scoped.view(workspace["id"], view["id"]) == view
            assert scoped.surface(surface["id"]) == surface
            assert reopened.audio.preferences(user["id"]) == preferences
    finally:
        reopened.close()
    bundle, destination = tmp_path / "backup", tmp_path / "restored"
    assert export(storage_state, bundle)["schema"] == SCHEMA
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert "state-provider.json" not in manifest["members"] and "state-binding" not in manifest["members"]
    restore(bundle, destination, True)
    restored = Service(settings(destination))
    try:
        assert not (destination / "state-provider.json").exists()
        assert restored.store.db.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
        for user, project, headers, workspace, view, surface, preferences in saved:
            assert restored.auth.identities.user(user["id"])["disabled"]
            with pytest.raises(Failure):
                restored.auth.resolve(headers["Authorization"][7:])
            assert restored.workspaces.get(workspace["id"]) == workspace
            assert restored.workspaces.view(workspace["id"], view["id"]) == view
            assert restored.workspaces.surface(surface["id"]) == surface
            assert restored.audio.preferences(user["id"]) == preferences
        assert all(not package["enabled"] and not package["grants"] for package in restored.modules.list())
    finally:
        restored.close()
    with closing(connect(destination / "state.sqlite3", readonly=True)) as database:
        assert database.execute("SELECT count(*) FROM workspace_views WHERE subject_id!=?", (LOCAL_OWNER,)).fetchone()[0] == count
        assert database.execute("SELECT count(*) FROM workspace_surfaces WHERE subject_id!=?", (LOCAL_OWNER,)).fetchone()[0] == count


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_nested_transactions_rollback_every_record_and_preserve_controls(storage_state, count):
    store = Store(storage_state / "state.sqlite3")
    try:
        for index in range(count):
            store.set_setting(f"control-{index}", {"value": index})
        with pytest.raises(StorageFailure, match="rolled back"):
            with store.lock, store.db:
                for index in range(count):
                    store.set_setting(f"new-{index}", {"created": index})
                    store.set_setting(f"control-{index}", {"modified": index})
                try:
                    with store.db:
                        raise ValueError("injected nested failure")
                except ValueError:
                    pass
        for index in range(count):
            assert store.get_setting(f"new-{index}", None) is None
            assert store.get_setting(f"control-{index}", None) == {"value": index}
        _, principal = Auth(store).issue("token")
        assert principal.subject_id == LOCAL_OWNER
    finally:
        store.close()
