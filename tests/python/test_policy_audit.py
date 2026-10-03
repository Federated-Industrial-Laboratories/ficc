# SPDX-License-Identifier: Apache-2.0
"""Keep security changes and audit receipts consistent across storage and cleanup failures."""

import sqlite3

import pytest
from policy_fixtures import activate, install_pack
from test_identity_projects import member
from test_policy_guards import Runner

from ficc import policy_provider


class CleanupRunner(Runner):
    fail_close = False

    def close(self):
        if self.fail_close:
            raise ValueError("Injected cleanup failure")
        super().close()


def events(service, action):
    return service.store.db.execute("SELECT target,outcome,actor,subject_id,project_id FROM audit "
                                    "WHERE action=:p0 ORDER BY id", ("policy." + action,)).fetchall()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_cleanup_failure_retains_committed_change_and_audit(policy_console, monkeypatch, count):
    client, service, material = policy_console
    monkeypatch.setattr(policy_provider, "prepare", lambda *args: CleanupRunner())
    digests = [install_pack(client, material, preset) for preset in ("managed", "contribution")]
    activate(client, digests[0])
    host = service.policies
    owner = client.get("/api/v1/session").json()["principal"]
    assert len(events(service, "activate")) == len(events(service, "publisher")) == 1
    for index in range(count):
        before = host.records.state()
        old = host.prepared.runner
        old.fail_close = True
        response = client.post("/api/v1/policy-activation", json={"digest": digests[(index + 1) % 2], "revision": before["revision"]})
        assert response.status_code == 503, response.text
        after = host.records.state()
        assert after["revision"] == before["revision"] + 1
        assert after["active"] != before["active"]
        assert list(events(service, "activate")[-1]) == [after["active"], "success", owner["id"], owner["subject_id"], owner["project_id"]]
        assert events(service, "cleanup")[-1][0:2] == (after["active"], "failed")
        assert not host.status()["ready"]
        assert client.get("/api/v1/workspaces").status_code == 503
        blocked = client.post("/api/v1/policy-activation", json={"digest": after["active"], "revision": after["revision"]})
        assert blocked.status_code == 503 and host.records.state() == after
        old.fail_close = False
    assert len(events(service, "activate")) == count + 1
    active = host.prepared.runner
    active.fail_close = True
    response = client.put("/api/v1/policy-publishers", json={"id": "example-publisher", "public_key": material["public_key"],
                                                           "enabled": False, "revision": 1})
    assert response.status_code == 503, response.text
    assert host.records.publishers()[0]["enabled"] is False
    assert len(events(service, "publisher")) == 2
    assert events(service, "cleanup")[-1][0:2] == ("example-publisher", "failed")
    active.fail_close = False
    assert client.put("/api/v1/policy-publishers", json={"id": "example-publisher", "public_key": material["public_key"],
                                                       "enabled": True, "revision": 2}).status_code == 200
    activate(client, digests[0])
    assert host.status()["ready"] and not host.retired
    assert client.get("/api/v1/workspaces").status_code == 200


@pytest.mark.parametrize("action", ["publisher", "install", "roles", "activate"])
def test_audit_write_failure_rolls_back_security_change(policy_console, monkeypatch, action):
    client, service, material = policy_console
    monkeypatch.setattr(policy_provider, "prepare", lambda *args: CleanupRunner())
    digest = install_pack(client, material)
    activate(client, digest)
    user, project, _, _ = member(service, "Audit rollback")
    host = service.policies
    state, publishers, packages = host.records.state(), host.records.publishers(), host.records.packages()
    prepared = host.prepared
    original = service.store.audit
    def fail(selected, *args, **kwargs):
        if selected == "policy." + action:
            raise sqlite3.OperationalError("Injected audit failure")
        return original(selected, *args, **kwargs)
    monkeypatch.setattr(service.store, "audit", fail)
    if action == "publisher":
        response = client.put("/api/v1/policy-publishers", json={"id": "example-publisher", "public_key": material["public_key"],
                                                               "enabled": False, "revision": 1})
    elif action == "install":
        import base64
        response = client.post("/api/v1/policy-packages", json={"archive_base64": base64.b64encode(material["contribution"]).decode()})
    elif action == "roles":
        response = client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}", json={"roles": ["observer"], "revision": 0})
    else:
        response = client.post("/api/v1/policy-activation", json={"digest": digest, "revision": state["revision"]})
    assert response.status_code == 503, response.text
    assert host.records.state() == state and host.records.publishers() == publishers and host.records.packages() == packages
    assert host.records.bindings(project["id"]) == []
    assert host.prepared is prepared and host.status()["ready"] and not host.retired
    assert client.get("/api/v1/workspaces").status_code == 200
