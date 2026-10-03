# SPDX-License-Identifier: Apache-2.0
"""Preserve unsaved legacy view ownership through upgrade and backup recovery."""

import sqlite3

import pytest
from fastapi.testclient import TestClient
from identity_fixtures import legacy_schema

from ficc.api import create_app
from ficc.backup import export, restore
from ficc.backup_database import SCHEMA, quiescent
from ficc.identity_store import LOCAL_OWNER, LOCAL_PROJECT
from ficc.service import Service
from ficc.settings import Settings
from ficc.workspace_schema import SurfaceUpdate, ViewUpdate


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("recover", [False, True])
@pytest.mark.parametrize("full", [False, True])
def test_unsaved_legacy_views_keep_owner_and_capacity(tmp_path, count, recover, full):
    state = tmp_path / "state"
    service = Service(Settings(state_dir=state, control=False))
    records = []
    for index in range(count):
        workspace = service.workspaces.create(f"Legacy workspace {index}")
        view, surface, tile = (f"{offset + index:032x}" for offset in (1024, 2048, 3072))
        layout = service.workspaces.save_surface(surface, SurfaceUpdate(revision=0, layout={"activeGroup": str(index)}, tiles=[{
            "id": tile, "workspace_id": workspace["id"], "view_id": view}]))
        records.append((workspace, view, surface, layout))
    service.close()
    with sqlite3.connect(state / "state.sqlite3") as db:
        legacy_schema(db, 6)
        db.execute("DELETE FROM workspace_views")
        quiescent(db)
        if full:
            import json
            for index in range(256):
                identity = f"{4096 + index:032x}"
                workspace = records[index % count][0]["id"]
                value = {"id": identity, "workspace_id": workspace, "revision": 1, "layout": {"activeGroup": str(index)}}
                db.execute("INSERT INTO workspace_views VALUES (?,?,?)", (identity, workspace, json.dumps(value)))
        quiescent(db)
    if recover:
        assert export(state, tmp_path / "backup")["schema"] == 6
        restore(tmp_path / "backup", tmp_path / "restored", True)
        state = tmp_path / "restored"
    app = create_app(Settings(state_dir=state, control=False, poll_interval=3600, stale_after=7200))
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        service = app.state.service
        token, _ = service.auth.issue("token")
        owner = {"Authorization": "Bearer " + token}
        attackers = []
        for index in range(count):
            user = service.auth.identities.create("user", f"Member {index}")
            service.auth.identities.membership(LOCAL_PROJECT, user["id"], ["workspaces:read", "workspaces:write"], 0)
            token, _ = service.auth.issue("token", subject_id=user["id"])
            attackers.append({"Authorization": "Bearer " + token})
        saved = service.store.db.execute("SELECT * FROM workspace_views ORDER BY id").fetchall()
        assert len(saved) == (256 if full else 0)
        for (workspace, view, surface, layout), attacker in zip(records, attackers, strict=True):
            url = f"/api/v1/workspaces/{workspace['id']}/views/{view}"
            assert client.get(url, headers=attacker).status_code == 404
            assert client.put(url, headers=attacker, json={"revision": 0, "layout": {}}).status_code == 404
            assert client.delete(url + "?revision=0", headers=attacker).status_code == 404
            assert client.get(url, headers=owner).json() == {
                "id": view, "workspace_id": workspace["id"], "revision": 0, "layout": {}}
            assert client.get("/api/v1/workspace-surfaces/" + surface, headers=owner).json() == layout
            result = client.put(url, headers=owner, json={"revision": 0, "layout": {"activeGroup": workspace["name"]}})
            assert result.status_code == (409 if full else 200)
        if full:
            assert service.store.db.execute("SELECT * FROM workspace_views ORDER BY id").fetchall() == saved
            # Existing layouts remain writable at the saved-view limit.
            first = saved[0]
            result = service.workspaces.save_view(first[1], first[0], ViewUpdate(revision=1, layout={"activeGroup": "Updated"}))
            assert result["revision"] == 2
        assert all(row[0] == LOCAL_OWNER for row in service.store.db.execute("SELECT subject_id FROM workspace_views"))
        quiescent(service.store.db)
    assert export(state, tmp_path / "upgraded-backup")["schema"] == SCHEMA
