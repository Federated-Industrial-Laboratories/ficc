# SPDX-License-Identifier: Apache-2.0
"""Use distinct project objects and synthetic retained receipts without repeating VM handshakes."""

import copy
import secrets
import time

import pytest
from ficc_node import vm_spec
from policy_fixtures import configure_policy
from project_module_fixtures import VM_SCOPES, checked, console, context, prepare

from ficc.errors import Failure
from ficc.module_capabilities import require_action
from ficc.module_vm_routes import instance_guard


def retained_receipt(service, record, digest):
    """Validate and persist a synthetic completed result for authority and restart checks."""
    now = time.time()
    targets = [{"node_id": record["node"], "profile": record["profile"], "vm_id": record["vm"],
                "expected": {"uuid": "0" * 32, "definition": "d" * 64, "state": "off"}, "state": "queued"}]
    preview = secrets.token_hex(16)
    value = {"id": secrets.token_hex(16), "actor": record["actor"].id, "key": secrets.token_hex(16),
             "digest": vm_spec.digest({"preview_id": preview, "action": "start", "targets": targets}),
             "package_digest": digest, "instance_id": record["instance"], "action": "start", "preview_id": preview,
             "controller": service.vms.controller, "created_at": now, "updated_at": now,
             "targets": [{**targets[0], "state": "observed", "observed_state": "running", "observed_at": now}]}
    service.vms.records.insert(value)
    return value


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distinct_project_panels_lists_and_retained_operation_authority(storage_state, policy_material, monkeypatch, count):
    configure_policy(storage_state)
    with console(storage_state, monkeypatch) as (client, service):
        records, digest, _grants = prepare(client, service, policy_material, count)
        values = [retained_receipt(service, record, digest) for record in records]
        for index, record in enumerate(records[:count]):
            peer = records[(index + 1) % len(records)]
            modules = checked(client.get("/api/v1/modules", headers=record["headers"]))["modules"]
            assert [item["digest"] for item in modules] == [digest]
            for grant in modules[0]["grants"]:
                assert grant["target_ids"] == [record["workspace"]["id"] if grant["capability"] == "workspace:read" else record["node"]]
            targets = checked(client.get("/api/v1/module-targets", headers=record["headers"]))["targets"]
            assert [item["id"] for item in targets["system"]] == [record["node"]]
            caller = service.auth.current(record["actor"].id)
            panel = service.auth.resources.module_instance(caller, record["workspace"]["id"], record["instance"])
            require_action(service, caller, record["workspace"]["id"], panel, "open-console", [record["node"]])
            with pytest.raises(Failure):
                require_action(service, caller, record["workspace"]["id"], panel, "open-console", [peer["node"]])
            body = {**context(record), "operation_id": values[index]["id"]}
            assert client.post("/api/v1/module-vms/operation", headers=peer["headers"], json=body).status_code == 404
            assert checked(client.post("/api/v1/module-vms/history", headers=record["headers"],
                                       json=context(record)))["operations"][0]["id"] == values[index]["id"]
            instance_guard(service, caller.id, type("Context", (), context(record))(), values[index])()
        affected = records[count - 1]
        before = copy.deepcopy(values[count - 1])
        checked(client.put(f"/api/v1/projects/{affected['project']['id']}/members/{affected['user']['id']}",
            json={"revision": 1, "scopes": [scope for scope in VM_SCOPES if scope != "vm:console"]}))
        with pytest.raises(Failure):
            require_action(service, affected["actor"], affected["workspace"]["id"], affected["panel"],
                           "open-console", [affected["node"]])
        control = records[0 if count > 1 else 1]
        require_action(service, control["actor"], control["workspace"]["id"], control["panel"],
                       "open-console", [control["node"]])
        assert service.vms.records.get(before["id"]) == before
    with console(storage_state, monkeypatch) as (_client, service):
        for index, record in enumerate(records[:count]):
            _secret, actor = service.auth.issue("token", subject_id=record["user"]["id"], project_id=record["project"]["id"])
            value = service.vms.records.get(values[index]["id"])
            assert value == values[index]
            instance_guard(service, actor.id, type("Context", (), context(record))(), value)()
