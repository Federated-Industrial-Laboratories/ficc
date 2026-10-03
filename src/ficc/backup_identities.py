# SPDX-License-Identifier: Apache-2.0
"""Validate identity references and private workspace ownership before recovery."""

import json

from .backup_modules import identity
from .identity_store import LOCAL_OWNER, LOCAL_PROJECT, PROJECT_SCOPES
from .workspace_schema import AudioPreferences


def records(db):
    users: dict[str, int] = {}
    projects: dict[str, int] = {}
    for table, values, recovery in (("identities", users, LOCAL_OWNER), ("projects", projects, LOCAL_PROJECT)):
        for key, label, disabled, revision in db.execute(f"SELECT * FROM {table}"):
            identity(key)
            if (not isinstance(label, str) or not label.strip() or len(label) > 80
                    or type(disabled) is not int or disabled not in {0, 1}
                    or type(revision) is not int or not 0 <= revision <= 2**53 - 1):
                raise ValueError("An identity or project record is invalid.")
            values[key] = disabled
        if values.get(recovery) != 0:
            raise ValueError("The local recovery identity or project is unavailable.")
    for project, subject, raw, revision in db.execute("SELECT * FROM project_memberships"):
        scopes = json.loads(raw)
        if (project not in projects or subject not in users or subject == LOCAL_OWNER
                or not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes)
                or len(scopes) != len(set(scopes)) or set(scopes) - PROJECT_SCOPES
                or type(revision) is not int or not 1 <= revision <= 2**53 - 1):
            raise ValueError("A project membership record is invalid.")
    for subject, project in db.execute("SELECT subject_id,project_id FROM credentials"):
        if subject not in users or project not in projects:
            raise ValueError("A credential has an invalid identity or project.")
    spaces = dict(db.execute("SELECT id,project_id FROM workspaces"))
    if any(project not in projects for project in spaces.values()):
        raise ValueError("A workspace has an invalid project.")
    views = {}
    for key, workspace, subject in db.execute("SELECT id,workspace_id,subject_id FROM workspace_views"):
        if subject not in users or workspace not in spaces:
            raise ValueError("A workspace view has an invalid owner.")
        views[key] = (workspace, subject)
    for raw, project, subject in db.execute("SELECT value,project_id,subject_id FROM workspace_surfaces"):
        if project not in projects or subject not in users:
            raise ValueError("A workspace surface has an invalid owner.")
        for tile in json.loads(raw)["tiles"]:
            if (spaces.get(tile["workspace_id"]) != project
                    or views.setdefault(tile["view_id"], (tile["workspace_id"], subject)) != (tile["workspace_id"], subject)):
                raise ValueError("A workspace surface crosses a project or user boundary.")
    for key, raw in db.execute("SELECT key,value FROM settings WHERE key LIKE 'audio.preferences.%'"):
        if key.removeprefix("audio.preferences.") not in users:
            raise ValueError("Audio preferences have an invalid owner.")
        AudioPreferences.model_validate(json.loads(raw))
