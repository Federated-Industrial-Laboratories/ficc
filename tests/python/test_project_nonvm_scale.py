# SPDX-License-Identifier: Apache-2.0
"""Check real panel authority with distinct projects and synthetic durable non-VM results."""

import json

import pytest
from policy_fixtures import configure_policy
from project_module_fixtures import bind_role, checked, console, context
from project_nonvm_fixtures import (
    BASE_SCOPES,
    KINDS,
    action_guard,
    history,
    host,
    prepare,
    status_read,
)

from ficc.errors import Failure
from ficc.module_vm_routes import Context, instance_guard


def permitted(client, service, record, kind):
    action_guard(service, record, kind)()
    if kind == "status":
        values = status_read(client, service, record)
        assert len(values) == 1 and values[0]["target"] == record["node"]
        assert values[0]["data"]["id"] == record["node"]
        assert values[0]["data"]["name"] == record["saved"]["name"]
        assert values[0]["data"]["resources"] == record["saved"]["resources"]
        resources = checked(client.get(f"/api/v1/nodes/{record['node']}/resources", headers=record["headers"]))
        assert resources["node_id"] == record["node"]
        assert resources["resources"] == record["saved"]["resources"]
    else:
        receipt = record["receipt"]
        operations = history(client, record, kind)["operations"]
        assert len(operations) == 1 and operations[0]["id"] == receipt["id"]
        assert operations[0]["outcomes"] == {"observed": 1}
        guard = instance_guard(service, record["actor"].id, Context(**context(record)), receipt)
        host(service, kind).local_authority(record["actor"].id, receipt, KINDS[kind]["read"], guard)
        assert host(service, kind).records.get(receipt["id"]) == receipt


def denied(client, service, record, kind):
    with pytest.raises(Failure) as error:
        action_guard(service, record, kind)()
    assert error.value.status == 403
    checked(client.post("/api/v1/module-invocations", headers=record["headers"],
        json={**context(record), "targets": [record["node"]], "action": "load"}), 403)
    if kind == "status":
        with pytest.raises(Failure) as error:
            status_read(client, service, record)
        assert error.value.status == 403
    else:
        history(client, record, kind, 403)
        checked(client.post(f"/api/v1/module-{kind}/operation", headers=record["headers"],
                            json={**context(record), "operation_id": record["receipt"]["id"]}), 403)
        assert host(service, kind).records.get(record["receipt"]["id"]) == record["receipt"]


@pytest.mark.parametrize("kind", ["admin", "containers", "status"])
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distinct_nonvm_projects_retained_results_and_current_authority(storage_state, policy_material,
                                                                      monkeypatch, count, kind):
    """Supplement real installed-panel workflows with lightweight authority and restart cohorts."""
    configure_policy(storage_state)
    with console(storage_state, monkeypatch) as (client, service):
        records = prepare(client, service, policy_material, kind, count)
        for key in ("user", "project", "workspace"):
            assert len({record[key]["id"] for record in records}) == max(2, count)
        for key in ("node", "instance"):
            assert len({record[key] for record in records}) == max(2, count)
        assert len({record["actor"].id for record in records}) == max(2, count)
        assert all(not record["actor"].local_owner for record in records)
        if kind != "status":
            assert len({record["receipt"]["id"] for record in records}) == max(2, count)
            assert len({record["receipt"]["targets"][0]["resource_id"] for record in records}) == max(2, count)
        for index, record in enumerate(records[:count]):
            peer = records[(index + 1) % len(records)]
            spaces = checked(client.get("/api/v1/workspaces", headers=record["headers"]))["workspaces"]
            assert [space["id"] for space in spaces] == [record["workspace"]["id"]]
            targets = checked(client.get("/api/v1/module-targets", headers=record["headers"]))["targets"]
            assert [item["id"] for item in targets["system"]] == [record["node"]]
            assert [item["id"] for item in targets["workspace"]] == [record["workspace"]["id"]]
            permitted(client, service, record, kind)
            with pytest.raises(Failure) as error:
                action_guard(service, record, kind, [peer["node"]])()
            assert error.value.status == 403
            checked(client.get(f"/api/v1/workspaces/{record['workspace']['id']}", headers=peer["headers"]), 404)
            if kind == "status":
                checked(client.get(f"/api/v1/nodes/{record['node']}/resources", headers=peer["headers"]), 403)
                with pytest.raises(Failure):
                    status_read(client, service, record, [peer["node"]])
            else:
                body = {**context(record), "operation_id": record["receipt"]["id"]}
                checked(client.post(f"/api/v1/module-{kind}/operation", headers=peer["headers"], json=body), 404)
                checked(client.post(f"/api/v1/module-{kind}/operation", headers=record["headers"],
                    json={**context(record), "operation_id": peer["receipt"]["id"]}), 409)
        affected, control = records[count - 1], records[0 if count > 1 else 1]
        retained_guard = action_guard(service, affected, kind)
        bind_role(client, affected, ["observer"], 1)
        with pytest.raises(Failure):
            retained_guard()
        denied(client, service, affected, kind)
        permitted(client, service, control, kind)
        bind_role(client, affected, [KINDS[kind]["role"]], 2)
        retained_guard()
        permitted(client, service, affected, kind)
        scopes = [scope for scope in BASE_SCOPES + KINDS[kind]["scopes"] if scope != KINDS[kind]["read"]]
        checked(client.put(f"/api/v1/projects/{affected['project']['id']}/members/{affected['user']['id']}",
                           json={"revision": 1, "scopes": scopes}))
        with pytest.raises(Failure):
            retained_guard()
        denied(client, service, affected, kind)
        permitted(client, service, control, kind)
    with console(storage_state, monkeypatch) as (client, service):
        for record in records:
            token, record["actor"] = service.auth.issue("token", subject_id=record["user"]["id"],
                                                       project_id=record["project"]["id"])
            record["headers"] = {"Authorization": "Bearer " + token}
            saved = service.store.node(record["node"])
            for key in ("id", "name", "profile", "host", "account", "port", "key_type", "key", "resources", "last_seen"):
                assert saved[key] == record["saved"][key]
            if kind != "status":
                assert host(service, kind).records.get(record["receipt"]["id"]) == record["receipt"]
            if record is affected:
                denied(client, service, record, kind)
            else:
                permitted(client, service, record, kind)
        if kind == "status":
            checked(client.get(f"/api/v1/nodes/{affected['node']}/resources", headers=affected["headers"]), 403)
        else:
            checked(client.post(f"/api/v1/module-{kind}/operation", headers=control["headers"],
                json={**context(control), "operation_id": affected["receipt"]["id"]}), 409)
    print(json.dumps({"kind": kind, "count": count, "distinct_objects": len(records),
                      "synthetic_receipts": len(records) if kind != "status" else 0,
                      "saved_samples": len(records), "late_row": count - 1, "restart": "preserved"}, sort_keys=True))
