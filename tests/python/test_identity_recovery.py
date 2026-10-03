# SPDX-License-Identifier: Apache-2.0
"""Check owner migration, restart persistence and recovery with fresh authority."""

import sqlite3

import pytest
from fastapi.testclient import TestClient
from identity_fixtures import legacy_schema
from test_identity_projects import member

from ficc.api import create_app
from ficc.auth import Auth
from ficc.backup import export, restore
from ficc.backup_database import SCHEMA, quiescent
from ficc.errors import Failure
from ficc.identity_store import LOCAL_OWNER, LOCAL_PROJECT, Identities
from ficc.service import Service
from ficc.settings import Settings
from ficc.store import Store
from ficc.workspace_schema import SurfaceUpdate, ViewUpdate
from ficc.workspace_store import WorkspaceStore


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_existing_owner_credentials_and_workspaces_migrate_atomically(tmp_path, monkeypatch, count):
    state = tmp_path / "state"
    service = Service(Settings(state_dir=state, control=False))
    records = []
    for index in range(count):
        token, original = service.auth.issue("token", f"Existing {index}", scopes=["workspaces:read", "workspaces:write"])
        workspace = service.workspaces.create(f"Existing workspace {index}")
        service.store.audit("workspace.create", workspace["id"], actor=original.id)
        records.append((token, original, workspace))
    service.close()
    with sqlite3.connect(state / "state.sqlite3") as db:
        legacy_schema(db, 6)
    from ficc import identity_store
    migrate = identity_store.initialize

    def interrupted(db):
        migrate(db)
        raise OSError("injected migration interruption")

    monkeypatch.setattr(identity_store, "initialize", interrupted)
    with pytest.raises(OSError, match="interruption"):
        Store(state / "state.sqlite3")
    with sqlite3.connect(state / "state.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 6
        assert not db.execute("SELECT name FROM sqlite_schema WHERE name='identities'").fetchall()
        assert "subject_id" not in {row[1] for row in db.execute("PRAGMA table_info(credentials)")}
    monkeypatch.setattr(identity_store, "initialize", migrate)
    upgraded = Store(state / "state.sqlite3")
    try:
        for token, original, workspace in records:
            principal = Auth(upgraded).resolve(token)
            assert principal.id == original.id and principal.expires_at == original.expires_at
            assert principal.scopes == original.scopes
            assert (principal.subject_id, principal.project_id) == (LOCAL_OWNER, LOCAL_PROJECT)
            assert WorkspaceStore(upgraded).scoped(principal).get(workspace["id"]) == workspace
        assert len(upgraded.events()) == count
        assert all(event["subject_id"] == LOCAL_OWNER for event in upgraded.events())
        assert upgraded.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA
    finally:
        upgraded.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_restore_preserves_projects_and_layouts_but_disables_member_login(tmp_path, count):
    state, destination, recovered = (tmp_path / name for name in ("state", "backup", "restored"))
    service = Service(Settings(state_dir=state, control=False))
    owners, spaces = [], []
    layouts = []
    for index in range(count):
        user, project, principal, headers = member(service, f"User {index}")
        scoped = service.workspaces.scoped(principal)
        workspace = scoped.create(f"Workspace {index}")
        view, surface, tile = (f"{offset + index:032x}" for offset in (1024, 2048, 3072))
        saved_view = scoped.save_view(workspace["id"], view, ViewUpdate(revision=0, layout={"activeGroup": str(index)}))
        saved_surface = scoped.save_surface(surface, SurfaceUpdate(revision=0, layout={"activeGroup": f"tile-{index}"}, tiles=[{
            "id": tile, "workspace_id": workspace["id"], "view_id": view}]))
        owners.append((user, project, headers["Authorization"][7:]))
        spaces.append(workspace)
        layouts.append((saved_view, saved_surface))
    private_records = {table: service.store.db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
                       for table in ("workspace_views", "workspace_surfaces")}
    service.close()
    # Restart retains both identity and credential ownership before any export.
    reopened = Store(state / "state.sqlite3")
    try:
        for user, project, secret in owners:
            principal = Auth(reopened).resolve(secret)
            assert (principal.subject_id, principal.project_id) == (user["id"], project["id"])
    finally:
        reopened.close()
    assert export(state, destination)["schema"] == SCHEMA
    restore(destination, recovered, True)
    app = create_app(Settings(state_dir=recovered, control=False, poll_interval=3600, stale_after=7200))
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        restored = app.state.service
        assert sorted(restored.workspaces.all(), key=lambda value: value["id"]) == sorted(spaces, key=lambda value: value["id"])
        assert len(restored.auth.identities.projects(LOCAL_OWNER)) == count + 1
        for table, expected in private_records.items():
            assert restored.store.db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall() == expected
        for user, project, secret in owners:
            assert restored.auth.identities.user(user["id"])["disabled"] is True
            with pytest.raises(Failure):
                restored.auth.resolve(secret)
            with pytest.raises(Failure):
                restored.auth.issue("bootstrap", subject_id=user["id"], project_id=project["id"])
        outsider = restored.auth.identities.create("user", "Other reader")
        for (user, project, secret), (view, surface) in zip(owners, layouts, strict=True):
            restored.auth.identities.update("user", user["id"], user["label"], False, 1)
            restored.auth.identities.membership(project["id"], outsider["id"], ["workspaces:read", "workspaces:write"], 0)
            token, _ = restored.auth.issue("token", subject_id=user["id"], project_id=project["id"])
            other, _ = restored.auth.issue("token", subject_id=outsider["id"], project_id=project["id"])
            headers = {"Authorization": "Bearer " + token}
            attack = {"Authorization": "Bearer " + other}
            view_url = f"/api/v1/workspaces/{view['workspace_id']}/views/{view['id']}"
            surface_url = "/api/v1/workspace-surfaces/" + surface["id"]
            assert client.get(view_url, headers=headers).json() == view
            assert client.get(surface_url, headers=headers).json() == surface
            assert client.get(view_url, headers=attack).status_code == 404
            assert client.put(view_url, headers=attack, json={"revision": view["revision"], "layout": {}}).status_code == 404
            assert client.get(surface_url, headers=attack).status_code == 404
            with pytest.raises(Failure):
                restored.auth.resolve(secret)
        _, principal = restored.auth.issue("bootstrap")
        assert principal.subject_id == LOCAL_OWNER
        quiescent(restored.store.db)


@pytest.mark.parametrize("change", ["user", "project", "view", "surface", "membership", "audio"])
def test_backup_rejects_cross_boundary_ownership(tmp_path, change):
    service = Service(Settings(state_dir=tmp_path / "state", control=False))
    try:
        _, project, principal, _ = member(service, "Member")
        local = service.workspaces.create("Local")
        scoped = service.workspaces.scoped(principal)
        workspace = scoped.create("Private")
        view, surface = "a" * 32, "b" * 32
        scoped.save_view(workspace["id"], view, ViewUpdate(revision=0, layout={}))
        scoped.save_surface(surface, SurfaceUpdate(revision=0, layout={}, tiles=[{
            "id": "c" * 32, "workspace_id": workspace["id"], "view_id": view}]))
        db = service.store.db
        if change == "user":
            db.execute("UPDATE identities SET disabled=1 WHERE id=?", (LOCAL_OWNER,))
        elif change == "project":
            db.execute("UPDATE workspaces SET project_id=? WHERE id=?", ("f" * 32, local["id"]))
        elif change == "view":
            db.execute("UPDATE workspace_views SET subject_id=? WHERE id=?", (LOCAL_OWNER, view))
        elif change == "surface":
            db.execute("UPDATE workspace_surfaces SET project_id=? WHERE id=?", (LOCAL_PROJECT, surface))
        elif change == "membership":
            db.execute("UPDATE project_memberships SET scopes=? WHERE project_id=?", ('["identities:manage"]', project["id"]))
        else:
            db.execute("INSERT INTO settings VALUES (?,?)", ("audio.preferences." + "f" * 32, '{"revision":0,"volume":0.5,"muted":false}'))
        with pytest.raises(ValueError):
            quiescent(db)
        assert Identities(service.store).project(project["id"])["id"] == project["id"]
    finally:
        service.close()
