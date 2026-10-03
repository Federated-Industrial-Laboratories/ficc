# SPDX-License-Identifier: Apache-2.0
"""Verify host authority even when a trusted evaluator fails or returns hostile decisions."""

import pytest
from policy_fixtures import activate, install_pack
from test_identity_projects import member

from ficc import policy_provider
from ficc.errors import Failure


class Runner:
    def __init__(self):
        self.hook = None
        self.closed = False

    def evaluate(self, envelope):
        assert not self.closed
        if self.hook:
            return self.hook(envelope)
        return [{"id": item["id"], "allow": True, "reason": "fixture_allow"} for item in envelope["requests"]]

    def close(self):
        self.closed = True


@pytest.fixture
def permissive(console, policy_material, monkeypatch):
    client, service = console
    monkeypatch.setattr(policy_provider, "prepare", lambda *args: Runner())
    digest = install_pack(client, policy_material)
    activate(client, digest)
    return client, service, digest


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("fault", ["missing", "duplicate", "reordered", "bool", "reason", "extra", "exception"])
def test_malformed_provider_decisions_are_rejected(count, fault):
    asks = [policy_provider.request("workspaces:read", {"subject_id": str(index)}) for index in range(count)]
    runner = Runner()
    decisions = runner.evaluate({"requests": asks})
    if fault == "missing":
        decisions.pop()
    elif fault == "duplicate":
        decisions[-1]["id"] = decisions[0]["id"] if count > 1 else "other-request"
    elif fault == "reordered":
        decisions.reverse()
        if count == 1:
            decisions[0]["id"] = "stale-request"
    elif fault == "bool":
        decisions[-1]["allow"] = 1
    elif fault == "reason":
        decisions[-1]["reason"] = "unsafe\nprivate detail"
    elif fault == "extra":
        decisions[-1]["authority"] = {"owner": True}
    def reply(envelope):
        if fault == "exception":
            raise RuntimeError("PRIVATE PROVIDER DETAIL")
        return decisions
    runner.hook = reply
    with pytest.raises(ValueError) as denied:
        policy_provider.evaluate(runner, asks, 17)
    assert "PRIVATE" not in str(denied.value)
    runner.hook = None
    assert len(policy_provider.evaluate(runner, asks, 18)) == count


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_allow_all_policy_cannot_extend_grants_or_recovery(permissive, count):
    client, service, digest = permissive
    for index in range(count):
        user, project, actor, headers = member(service, f"Restricted {index}", scopes=["workspaces:read"])
        assert client.get("/api/v1/workspaces", headers=headers).status_code == 200
        assert client.post("/api/v1/workspaces", headers=headers, json={"name": f"Denied {index}"}).status_code == 403
        for body in ({"digest": digest}, {"subject_id": user["id"]}, {"project_id": project["id"]}):
            assert client.post("/api/v1/policy-preview", headers=headers,
                               json={**body, "requests": [{"action": "workspaces:write"}]}).status_code == 403
        preview = client.post("/api/v1/policy-preview", headers=headers,
                              json={"requests": [{"action": "workspaces:write", "labels": {"local_owner": True}}]})
        assert preview.status_code == 200
        assert preview.json()["decisions"][0] == {"action": "workspaces:write", "host_allowed": False,
                                                 "policy_allowed": True, "allowed": False, "reason": "host_grant_denied"}
        assert service.auth.current(actor.id).scopes == ["workspaces:read"]
    limited, _ = service.auth.issue("token", scopes=["policies:manage"], node_ids=[])
    assert client.get("/api/v1/policies", headers={"Authorization": "Bearer " + limited}).status_code == 403
    assert service.workspaces.all() == []


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_authority_change_during_evaluation_prevents_mutation(permissive, count):
    client, service, _ = permissive
    runner = service.policies.prepared.runner
    for index in range(count):
        user, project, actor, headers = member(service, f"Changed {index}", scopes=["workspaces:read", "workspaces:write"])
        def revoke(envelope):
            runner.hook = None
            service.policies.records.bind(project["id"], user["id"], [], 0)
            return runner.evaluate(envelope)
        runner.hook = revoke
        response = client.post("/api/v1/workspaces", headers=headers, json={"name": f"Stale {index}"})
        assert response.status_code == 409, response.text
        assert response.json()["error"]["code"] == "policy_changed"
        assert service.auth.current(actor.id).id == actor.id
        assert client.get("/api/v1/workspaces", headers=headers).json() == {"workspaces": []}
    assert service.workspaces.all() == []


def test_failure_stays_closed_and_failed_replacement_preserves_policy(permissive, monkeypatch):
    client, service, digest = permissive
    state = service.policies.records.state()
    runner = service.policies.prepared.runner
    user, project, _, headers = member(service, "Valid member", scopes=["workspaces:read"])
    def fail(*args):
        raise ValueError("Unavailable candidate")
    with monkeypatch.context() as patch:
        patch.setattr(policy_provider, "prepare", fail)
        response = client.post("/api/v1/policy-activation", json={"digest": digest, "revision": state["revision"]})
        assert response.status_code == 400
    assert service.policies.records.state() == state
    assert service.policies.prepared.runner is runner and not runner.closed
    assert client.get("/api/v1/workspaces", headers=headers).status_code == 200
    runner.hook = lambda envelope: []
    assert client.get("/api/v1/workspaces", headers=headers).status_code == 503
    runner.hook = None
    assert client.get("/api/v1/workspaces", headers=headers).status_code == 503
    assert client.get("/api/v1/policies").status_code == 200
    activate(client, digest)
    assert runner.closed
    assert client.get("/api/v1/workspaces", headers=headers).status_code == 200
    result = client.post("/api/v1/policy-activation", json={"digest": digest, "revision": state["revision"]})
    assert result.status_code == 409
    assert client.get("/api/v1/workspaces", headers=headers).status_code == 200


def test_privileged_preview_rechecks_owner_after_candidate_preparation(permissive, monkeypatch):
    client, service, digest = permissive
    _, actor = service.auth.issue("token")
    def revoke(*args):
        service.auth.revoke(actor.id)
        return Runner()
    monkeypatch.setattr(policy_provider, "prepare", revoke)
    with pytest.raises(Failure) as denied:
        service.policies.preview(actor.id, [{"action": "workspaces:read"}], digest=digest)
    assert denied.value.status == 401
    assert client.get("/api/v1/policies").status_code == 200


def test_invalid_administration_inputs_have_safe_errors(permissive):
    client, service, digest = permissive
    original = service.policies.records.state()
    for archive in ("!not-base64", "bm90LXppcA=="):
        response = client.post("/api/v1/policy-packages", json={"archive_base64": archive})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_policy"
    assert client.put("/api/v1/policy-publishers", json={"id": "invalid/key", "public_key": "not-a-key",
                                                       "enabled": True, "revision": 0}).status_code == 400
    assert client.post("/api/v1/policy-preview", json={"requests": [{"action": "unsupported:action"}]}).status_code == 400
    assert service.policies.records.state() == original


def test_preview_rechecks_the_callers_credential_after_evaluation(permissive, monkeypatch):
    _, service, _ = permissive
    _, actor = service.auth.issue("token")
    runner = Runner()
    def revoke(envelope):
        if envelope["requests"][0]["action"] == "policy:probe":
            return [{"id": item["id"], "allow": False, "reason": "probe"} for item in envelope["requests"]]
        runner.hook = None
        service.auth.revoke(actor.id)
        return runner.evaluate(envelope)
    runner.hook = revoke
    monkeypatch.setattr(policy_provider, "prepare", lambda *args: runner)
    with pytest.raises(Failure) as denied:
        service.policies.preview(actor.id, [{"action": "workspaces:read"}])
    assert denied.value.status == 401
