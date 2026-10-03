# SPDX-License-Identifier: Apache-2.0
"""Check distinct module callers, playback preferences and unaffected project grants."""

import secrets

import pytest
from test_identity_projects import member
from test_workspaces import installed

from ficc.errors import Failure


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_module_queue_and_audio_isolation_with_unaffected_members(console, monkeypatch, count):
    client, service = console
    projects = [service.auth.identities.create("project", name) for name in ("Affected", "Control")]
    cohorts = [[member(service, f"{project['label']} {i}", project) for i in range(count)] for project in projects]
    spaces = [client.post("/api/v1/workspaces", headers=records[0][3], json={"name": project["label"]}).json()
              for records, project in zip(cohorts, projects, strict=True)]
    capabilities = ["workspace:read", "audio:playback"]
    checksum = installed(client, [space["id"] for space in spaces], capabilities)
    panels = []
    preferences = []
    for group, (records, space) in enumerate(zip(cohorts, spaces, strict=True)):
        items = [{"id": secrets.token_hex(16), "digest": checksum, "title": f"Audio {group}/{i}",
                  "state": {"notes": f"Project content {group}/{i}"}} for i in range(count)]
        panels.append(items)
        result = client.put(f"/api/v1/workspaces/{space['id']}", headers=records[0][3],
                            json={"name": space["name"], "revision": 0, "instances": items})
        assert result.status_code == 200, result.text
        values = []
        for index, (_, _, _, headers) in enumerate(records):
            body = {"revision": 0, "volume": (index + group + 1) / 100, "muted": bool(group)}
            result = client.put("/api/v1/audio/preferences", headers=headers, json=body)
            assert result.status_code == 200
            values.append({**body, "revision": 1})
        preferences.append(values)
    called = []

    async def invoke(digest, action, targets, parameters, check, **kwargs):
        called.append((digest, list(targets)))
        if targets == [spaces[0]["id"]]:
            with service.store.lock, service.store.db:
                service.store.db.execute("DELETE FROM module_grants WHERE digest=? AND target_id=?", (digest, targets[0]))
        check()
        return {"targets": targets, "action": action}

    monkeypatch.setattr(service.module_runtime, "invoke", invoke)
    for index in range(count):
        user, project, principal, headers = cohorts[0][index]
        _, _, control, other = cohorts[1][index]
        for own, space in ((headers, spaces[0]), (other, spaces[1])):
            modules = client.get("/api/v1/modules", headers=own).json()["modules"]
            assert len(modules) == 1
            assert all(grant["target_ids"] == [space["id"]] for grant in modules[0]["grants"])
        control_body = {"instance_id": panels[1][index]["id"], "surface_id": secrets.token_hex(16)}
        control_lease = client.post("/api/v1/audio/leases", headers=other, json=control_body)
        assert control_lease.status_code == 200
        body = {"instance_id": panels[0][index]["id"], "surface_id": secrets.token_hex(16)}
        assert client.post("/api/v1/audio/leases", headers=other, json=body).status_code == 404
        lease = client.post("/api/v1/audio/leases", headers=headers, json=body)
        assert lease.status_code == 200
        invocation = {"workspace_id": spaces[0]["id"], "instance_id": body["instance_id"],
                      "targets": [spaces[0]["id"]], "action": "inspect"}
        assert client.post("/api/v1/module-invocations", headers=other, json=invocation).status_code == 404
        assert client.post("/api/v1/module-invocations", headers=headers, json=invocation).status_code == 403
        assert client.get("/api/v1/modules", headers=headers).json()["modules"] == []
        result = client.post("/api/v1/module-invocations", headers=other, json={
            "workspace_id": spaces[1]["id"], "instance_id": control_body["instance_id"],
            "targets": [spaces[1]["id"]], "action": "inspect"})
        assert result.status_code == 200 and result.json()["targets"] == [spaces[1]["id"]]
        service.auth.identities.membership(project["id"], user["id"], ["workspaces:read"], 1)
        with pytest.raises(Failure):
            service.audio.heartbeat(lease.json()["id"], principal.id, body["surface_id"])
        assert lease.json()["id"] not in service.audio.leases
        control_id = control_lease.json()["id"]
        assert service.audio.heartbeat(control_id, control.id, control_body["surface_id"])["id"] == control_id
        service.audio.release(control_id, control.id, control_body["surface_id"])
        assert client.get("/api/v1/audio/preferences", headers=other).json() == preferences[1][index]
        assert service.audio.preferences(user["id"]) == preferences[0][index]
        # Restore only the removed project's grants for the next distinct queued caller.
        with service.store.lock, service.store.db:
            service.store.db.executemany("INSERT INTO module_grants VALUES (?,?,?)",
                                        [(checksum, capability, spaces[0]["id"]) for capability in capabilities])
    assert len(called) == 2 * count and not service.audio.leases
    for index, (_, _, control, headers) in enumerate(cohorts[1]):
        assert service.auth.current(control.id).public() == control.public()
        assert client.get("/api/v1/audio/preferences", headers=headers).json() == preferences[1][index]
        saved = client.get(f"/api/v1/workspaces/{spaces[1]['id']}", headers=headers).json()
        assert saved["instances"][index]["state"] == {"notes": f"Project content 1/{index}"}
