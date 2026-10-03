# SPDX-License-Identifier: Apache-2.0
"""Check current host and real OPA authority in bounded, object-bound batches."""

import pytest
from conftest import node
from policy_fixtures import activate, install_pack
from project_module_fixtures import checked
from resource_fixtures import assign
from test_identity_projects import member

from ficc.errors import Failure


def subject(client, service, count):
    user, project, actor, _headers = member(service, "Batch VM operator", scopes=["vm:read", "vm:console"])
    nodes = [f"{index + 100:032x}" for index in range(count)]
    for index, identity in enumerate(nodes):
        service.store.save_node({**node(index), "id": identity})
    assign(client, project, nodes)
    checked(client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}",
                       json={"revision": 0, "roles": ["vm-operator"]}))
    requests = [(scope, identity, None) for identity in nodes for scope in ("vm:read", "vm:console")]
    return user, project, actor, nodes, requests


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_project_policy_batches_bind_every_resource_and_recheck_without_a_cache(policy_console, monkeypatch, count):
    client, service, material = policy_console
    user, project, actor, nodes, requests = subject(client, service, count)
    activate(client, install_pack(client, material))
    runner = service.policies.prepared.runner
    evaluate, seen = runner.evaluate, []

    def record(envelope):
        seen.append([(item["action"], item["authority"]["node_id"], item["authority"]["root_id"])
                     for item in envelope["requests"]])
        return evaluate(envelope)

    monkeypatch.setattr(runner, "evaluate", record)
    service.policies.check_many(actor, requests + requests)
    assert [item for batch in seen for item in batch] == requests
    assert [len(batch) for batch in seen] == ([2] if count == 1 else [64, 64])
    seen.clear()
    with pytest.raises(Failure):
        service.policies.check_many(actor, [*requests, ("vm:read", "f" * 32, None)])
    assert not seen
    with service.store.lock, service.store.db:
        service.policies.records.bind(project["id"], user["id"], ["vm-observer"], 1)
    with pytest.raises(Failure) as denied:
        service.policies.check_many(actor, requests)
    assert denied.value.code == "policy_denied"
    service.policies.check_many(actor, [("vm:read", identity, None) for identity in nodes])


@pytest.mark.parametrize("changed", ["membership", "resources", "roles", "revision", "credential"])
def test_project_policy_batch_detects_changes_after_actual_evaluation(policy_console, monkeypatch, changed):
    client, service, material = policy_console
    user, project, actor, nodes, requests = subject(client, service, 1)
    activate(client, install_pack(client, material))
    runner = service.policies.prepared.runner
    evaluate = runner.evaluate

    def mutate(envelope):
        results = evaluate(envelope)
        with service.store.lock, service.store.db:
            if changed == "membership":
                service.auth.identities.membership(project["id"], user["id"], ["vm:read"], 1)
            elif changed == "resources":
                service.auth.resources.save(project["id"], [], [], 1)
            elif changed == "roles":
                service.policies.records.bind(project["id"], user["id"], ["vm-observer"], 1)
            elif changed == "revision":
                service.policies.records.bump()
            else:
                service.auth.revoke(actor.id)
        return results

    monkeypatch.setattr(runner, "evaluate", mutate)
    with pytest.raises(Failure) as denied:
        service.policies.check_many(actor, requests)
    assert denied.value.status in {401, 403, 409}
    assert service.auth.resources.get(project["id"])["node_ids"] == ([] if changed == "resources" else nodes)


def test_project_batch_without_policy_still_requires_current_host_grants(console):
    client, service = console
    user, project, actor, _nodes, requests = subject(client, service, 1)
    assert not service.policies.required
    service.policies.check_many(actor, requests)
    with service.store.lock, service.store.db:
        service.auth.identities.membership(project["id"], user["id"], ["vm:read"], 1)
    with pytest.raises(Failure) as denied:
        service.policies.check_many(actor, requests)
    assert denied.value.status == 403
