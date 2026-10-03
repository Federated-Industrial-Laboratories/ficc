# SPDX-License-Identifier: Apache-2.0
"""Keep unrelated observation processes alive during member session changes."""

import asyncio
import signal
import sys

import pytest
from conftest import node
from test_identity_projects import member

from ficc.errors import Failure
from ficc.ssh_master import Master


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_member_switch_and_logout_preserve_owner_observers(console, count):
    client, service = console
    records = [member(service, f"Operator {i}", scopes=["workspaces:read"]) for i in range(count)]
    destination = service.auth.identities.create("project", "Destination")
    sessions = []
    for user, _, _, _ in records:
        service.auth.identities.membership(destination["id"], user["id"], ["workspaces:read", "workspaces:write"], 0)
    for user, project, _, _ in records:
        sessions.append(service.auth.issue("session", subject_id=user["id"], project_id=project["id"]))
    service.store.save_node(node())

    async def start():
        masters = []
        for index in range(count + 1):
            master = Master(f"observation-{index}", [sys.executable, "-c", "import time; time.sleep(120)"])
            service.ssh.masters.current[f"node-{index}"] = master
            service.ssh.masters.watchers.add(master.watcher)
            master.watcher.add_done_callback(service.ssh.masters.watchers.discard)
            masters.append(master)
        return masters

    masters = client.portal.call(start)
    try:
        for (secret, old), (_, project, unchanged, headers) in zip(sessions, records, strict=True):
            client.cookies.clear()
            client.cookies.set("ficc_session", secret)
            result = client.post("/api/v1/session/project", headers={"X-CSRF-Token": old.csrf},
                                 json={"project_id": destination["id"]})
            assert result.status_code == 200, result.text
            fresh = service.auth.current(result.json()["principal"]["id"])
            assert fresh.scopes == ["workspaces:read"] and fresh.expires_at == old.expires_at
            assert fresh.subject_id == old.subject_id and fresh.csrf != old.csrf
            with pytest.raises(Failure):
                service.auth.current(old.id)
            assert client.get("/api/v1/workspaces", headers={"X-FICC-Project": project["id"]}).status_code == 409
            assert client.get("/api/v1/workspaces", headers={"X-FICC-Session": old.id}).status_code == 409
            assert client.delete("/api/v1/session", headers={"X-CSRF-Token": fresh.csrf}).status_code == 200
            with pytest.raises(Failure):
                service.auth.current(fresh.id)
            assert client.get("/api/v1/session", headers=headers).json()["principal"] == unchanged.public()
            assert all(master.alive() for master in masters)
        # Owner revocation still closes its selected connection and preserves others.
        _, limited = service.auth.issue("token", node_ids=["node-0"])
        service.auth.revoke(limited.id)

        async def reaped(master):
            await asyncio.wait_for(asyncio.shield(master.watcher), 5)

        client.portal.call(reaped, masters[0])
        assert masters[0].process.returncode == -signal.SIGKILL
        assert all(master.alive() for master in masters[1:])
        _, owner = service.auth.issue("token")
        service.auth.revoke(owner.id)
        for master in masters[1:]:
            client.portal.call(reaped, master)
            assert master.process.returncode == -signal.SIGKILL
        assert not service.ssh.masters.current
    finally:
        client.portal.call(service.ssh.masters.close)
