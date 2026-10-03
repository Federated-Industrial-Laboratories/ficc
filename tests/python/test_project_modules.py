# SPDX-License-Identifier: Apache-2.0
"""Check project panels, real sandbox execution, OPA roles and durable VM receipts."""

import copy
import json
import secrets
from functools import partial

import pytest
from policy_fixtures import configure_policy
from project_module_fixtures import (
    VM_SCOPES,
    bind_role,
    checked,
    console,
    context,
    invoke,
    prepare,
    transport,
)
from resource_fixtures import assign

from ficc.errors import Failure
from ficc.identity_store import PROJECT_SCOPES
from ficc.module_vm_routes import instance_guard
from ficc.workspace_schema import WorkspaceUpdate


def test_project_module_workflow_and_durable_project_join(storage_state, policy_material, monkeypatch, tmp_path):
    count = 1
    configure_policy(storage_state)
    with console(storage_state, monkeypatch) as (client, service):
        records, digest, _grants = prepare(client, service, policy_material, count)
        providers = transport(service, monkeypatch, tmp_path / "node-receipts", records)
        for index, record in enumerate(records[:count]):
            peer = records[(index + 1) % len(records)]
            modules = checked(client.get("/api/v1/modules", headers=record["headers"]))["modules"]
            assert [module["digest"] for module in modules] == [digest]
            for grant in modules[0]["grants"]:
                assert grant["target_ids"] == [record["workspace"]["id"] if grant["capability"] == "workspace:read" else record["node"]]
            targets = checked(client.get("/api/v1/module-targets", headers=record["headers"]))
            assert [item["id"] for item in targets["targets"]["system"]] == [record["node"]]
            assert targets["targets"]["adapter-profile"] == [] and "provider:admin" not in targets["capabilities"]
            profiles = checked(client.get("/api/v1/vm-profiles", headers=record["headers"]))["profiles"]
            assert [item["node_id"] for item in profiles] == [record["node"]]
            inventory = invoke(client, record)["results"][0]["data"]
            assert not inventory["notice"] and inventory["rows"][0]["id"] == record["vm"]
            reference = invoke(client, record, "open-console", {"vm_ids": [record["vm"]]})["results"][0]["data"]["viewer_ref"]
            assert service.viewers.current(reference, record["actor"].id)["descriptor"]["node_id"] == record["node"]
            record["reference"] = reference
            with pytest.raises(Failure):
                service.viewers.current(reference, peer["actor"].id)
            assert client.get(f"/api/v1/workspaces/{record['workspace']['id']}", headers=peer["headers"]).status_code == 404
            stolen = {**context(record), "targets": [record["node"]], "action": "load"}
            assert client.post("/api/v1/module-invocations", headers=peer["headers"], json=stolen).status_code == 404
            assert client.post("/api/v1/module-invocations", headers=record["headers"],
                               json={**stolen, "targets": [peer["node"]]}).status_code == 403
            assert client.post(f"/api/v1/modules/{digest}/activation", headers=record["headers"],
                               json={"enabled": False}).status_code == 403
            assert client.put(f"/api/v1/nodes/{record['node']}/vm-profile", headers=record["headers"],
                              json={"connection": "system"}).status_code == 403
            bind_role(client, record, ["vm-observer"], 1)
            assert invoke(client, record)["results"][0]["data"]["rows"]
            invoke(client, record, "open-console", {"vm_ids": [record["vm"]]}, status=403)
            invoke(client, record, "preview-start", {"vm_ids": [record["vm"]]}, status=403)
            with pytest.raises(Failure):
                service.viewers.current(reference, record["actor"].id)
            bind_role(client, record, ["vm-operator"], 2)
            preview = invoke(client, record, "preview-start", {"vm_ids": [record["vm"]]})["results"][0]["data"]
            body = {**context(record), "preview_id": preview["preview_id"], "confirm": True}
            operation = checked(client.post("/api/v1/module-vms/commit", headers={**record["headers"],
                                "Idempotency-Key": secrets.token_hex(16)}, json=body))
            assert operation["targets"][0]["state"] == "accepted"
            record["operation"] = operation["id"]
            body = {**context(record), "operation_id": operation["id"]}
            assert client.post("/api/v1/module-vms/operation", headers=peer["headers"], json=body).status_code == 404
            operation = checked(client.post("/api/v1/module-vms/operation", headers=record["headers"], json=body))
            assert operation["targets"][0]["state"] == "observed" and len(providers[record["node"]].calls) == 1
            assert client.put(f"/api/v1/workspaces/{record['workspace']['id']}", headers=record["headers"],
                              json={"revision": 1, "name": "Moved", "instances": []}).status_code == 409
        # Receipt rows and their project workspaces survive controller replacement.
    with console(storage_state, monkeypatch) as (client, service):
        transport(service, monkeypatch, tmp_path / "node-receipts", records, providers)
        for index, record in enumerate(records[:count]):
            secret, actor = service.auth.issue("token", subject_id=record["user"]["id"], project_id=record["project"]["id"])
            headers = {"Authorization": "Bearer " + secret}
            history = checked(client.post("/api/v1/module-vms/history", headers=headers, json=context(record)))
            assert [item["id"] for item in history["operations"]] == [record["operation"]]
            peer = records[(index + 1) % len(records)]
            # A shared system assignment cannot transfer another project's receipt.
            assign(client, peer["project"], [peer["node"], record["node"]], revision=1)
            body = {**context(record), "operation_id": record["operation"]}
            assert client.post("/api/v1/module-vms/operation", headers=peer["headers"], json=body).status_code == 404
            value = service.vms.records.get(record["operation"])
            check = instance_guard(service, actor.id, type("Context", (), context(record))(), value)
            check()
            before = copy.deepcopy(value)
            # Simulate loss of the persistent join, without editing an accepted outcome.
            with service.store.lock, service.store.db:
                service.store.db.execute("UPDATE workspaces SET project_id=:p0 WHERE id=:p1",
                                         (peer["project"]["id"], record["workspace"]["id"]))
            with pytest.raises(Failure):
                check()
            assert service.vms.records.get(record["operation"]) == before
            with service.store.lock, service.store.db:
                service.store.db.execute("UPDATE workspaces SET project_id=:p0 WHERE id=:p1",
                                         (record["project"]["id"], record["workspace"]["id"]))
            check()
            assign(client, peer["project"], [peer["node"]], revision=2)


@pytest.mark.parametrize("changed", ["membership", "resource", "package", "instance"])
def test_project_viewer_reference_checks_current_authority(policy_console, monkeypatch, tmp_path, changed):
    client, service, material = policy_console
    records, digest, _grants = prepare(client, service, material, 1)
    transport(service, monkeypatch, tmp_path / "receipts", records)
    references = [invoke(client, record, "open-console", {"vm_ids": [record["vm"]]})["results"][0]["data"]["viewer_ref"]
                  for record in records]
    affected, control = records
    if changed == "membership":
        checked(client.put(f"/api/v1/projects/{affected['project']['id']}/members/{affected['user']['id']}",
                           json={"scopes": [scope for scope in VM_SCOPES if scope != "vm:console"], "revision": 1}))
    elif changed == "resource":
        assign(client, affected["project"], [], revision=1)
    elif changed == "package":
        # Delete only this target grant to demonstrate an unaffected peer in the same package.
        with service.store.lock, service.store.db:
            service.store.db.execute("DELETE FROM module_grants WHERE digest=:p0 AND capability=:p1 AND target_id=:p2",
                                     (digest, "vm:console", affected["node"]))
    else:
        checked(client.put(f"/api/v1/workspaces/{affected['workspace']['id']}", headers=affected["headers"],
                           json={"revision": 1, "name": "Panel removed", "instances": []}))
    with pytest.raises(Failure):
        service.viewers.current(references[0], affected["actor"].id)
    assert service.viewers.current(references[1], control["actor"].id)["descriptor"]["node_id"] == control["node"]
    assert invoke(client, control)["results"][0]["data"]["rows"]


def test_project_scope_names_and_policy_roles_are_explicit():
    from project_module_fixtures import ROOT
    data = json.loads((ROOT / "policy-packs/managed/payload/data.json").read_text())["roles"]
    privileged = {"modules:manage", "nodes:write", "providers:write", "provider:admin", "identities:manage", "policies:manage"}
    assert not privileged & PROJECT_SCOPES
    assert not {"vm:console", "vm:power"} & set(data["vm-observer"])
    for role in ("vm-observer", "vm-operator", "container-operator", "system-operator"):
        assert set(data[role]) <= PROJECT_SCOPES and not set(data[role]) & privileged
    for role in ("observer", "operator", "node-administrator"):
        assert not any(scope.startswith(("vm:", "container:", "admin:")) for scope in data[role])


def test_adapter_stays_owner_only_with_vm_grants(policy_console, monkeypatch, tmp_path):
    from test_module_adapter_manifest import adapter_package
    from test_module_adapters import Transport
    from test_modules_packages import bundle

    from ficc.module_adapter_vm import AdapterVMs
    from ficc.module_adapters import Adapters
    from ficc.modules import inspect_archive

    client, service, material = policy_console
    records, digest, _grants = prepare(client, service, material, 1)
    transport(service, monkeypatch, tmp_path / "receipts", records)
    record = records[0]
    owner = service.auth.resolve(client.cookies.get("ficc_session")).id
    adapter = inspect_archive(bundle(*adapter_package(id="org.example.project-adapter")))
    service.modules.install(adapter, adapter.digest)
    adapters = Adapters(service, transport=Transport())
    profile = client.portal.call(adapters.create, owner, adapter.digest, "linux-ssh", record["node"], "c" * 32)
    client.portal.call(partial(adapters.grant, owner, profile["id"], profile["revision"], confirmed=True))
    profile = adapters.profile(profile["id"])
    host = AdapterVMs(service, adapters)
    service.modules.require(adapter.digest, "provider:admin", [profile["id"]])
    # The synthetic provider has a registered profile and account grant; host policy remains real.
    for capability in ("vm:read", "vm:power", "vm:console"):
        service.authorize(record["actor"].id, capability, record["node"])
        service.modules.require(digest, capability, [record["node"]])
        host.guard(owner, digest, record["node"], capability, profile, lambda: None)()
        with pytest.raises(Failure, match="does not permit"):
            host.guard(record["actor"].id, digest, record["node"], capability, profile, lambda: None)
    with pytest.raises(Failure):
        host.local_authority(record["actor"].id, {}, "vm:read", lambda: None)


def test_project_panel_cannot_add_unassigned_targets(policy_console, monkeypatch):
    client, service, material = policy_console
    records, digest, _grants = prepare(client, service, material, 1)
    first, other = records
    body = {"revision": 1, "name": first["workspace"]["name"], "instances": [
        {**first["panel"], "targets": [other["node"]]}]}
    assert client.put(f"/api/v1/workspaces/{first['workspace']['id']}", headers=first["headers"], json=body).status_code == 403
    body["instances"] = [{**first["panel"], "id": other["instance"]}]
    assert client.put(f"/api/v1/workspaces/{first['workspace']['id']}", headers=first["headers"], json=body).status_code == 409
    # Current digest and target changes stop an already captured operation guard.
    value = {"instance_id": first["instance"], "package_digest": digest, "targets": [{"node_id": first["node"]}]}
    check = instance_guard(service, first["actor"].id, type("Context", (), context(first))(), value)
    for changes in ({"digest": "f" * 64}, {"targets": []}):
        current = service.workspaces.get(first["workspace"]["id"])
        service.workspaces.update(current["id"], WorkspaceUpdate(revision=current["revision"], name=current["name"],
            instances=[{**first["panel"], **changes}]))
        with pytest.raises(Failure):
            check()
