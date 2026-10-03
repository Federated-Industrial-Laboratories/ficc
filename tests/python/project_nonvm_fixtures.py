# SPDX-License-Identifier: Apache-2.0
"""Build distinct panel authority with synthetic profiles, receipts and saved samples."""

import secrets
import time

from conftest import node, sample
from ficc_node import admin_spec, container_spec
from policy_fixtures import activate, install_pack
from project_module_fixtures import checked, context, installed
from resource_fixtures import assign
from test_identity_projects import member

from ficc.module_admin_store import intent as admin_intent
from ficc.module_broker import handler
from ficc.module_capabilities import require_action
from ficc.module_containers_store import intent as container_intent
from ficc.module_vm_store import node_identity
from ficc.modules.broker_protocol import BrokerCall

BASE_SCOPES = ["nodes:read", "workspaces:read", "workspaces:write", "modules:read", "modules:execute"]
KINDS = {
    "admin": {"name": "system-admin", "role": "system-operator", "read": "admin:read",
              "scopes": ["admin:read", "admin:logs", "admin:services", "admin:power"]},
    "containers": {"name": "containers", "role": "container-operator", "read": "container:read",
                   "scopes": ["container:read", "container:logs", "container:power"]},
    "status": {"name": "system-status", "role": "system-operator", "read": "resources:read",
               "scopes": ["resources:read"]},
}


def prepare(client, service, material, kind, count):
    """Install the supplied panel and signed policy for distinct non-owner projects."""
    settings = KINDS[kind]
    records = []
    for index in range(max(2, count)):
        user, project, actor, headers = member(service, f"Panel member {index}",
                                               scopes=BASE_SCOPES + settings["scopes"])
        saved = {**node(index), "id": secrets.token_hex(16), "resources": sample(index)["resources"],
                 "last_seen": time.time(), "state": "online"}
        service.store.save_node(saved)
        assign(client, project, [saved["id"]])
        workspace = checked(client.post("/api/v1/workspaces", headers=headers,
                                        json={"name": f"Panel project {index}"}), 201)
        checked(client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}",
                           json={"revision": 0, "roles": [settings["role"]]}))
        records.append({"user": user, "project": project, "actor": actor, "headers": headers,
                        "node": saved["id"], "saved": saved, "workspace": workspace,
                        "instance": secrets.token_hex(16)})
    digest, _grants = installed(client, [item["workspace"]["id"] for item in records],
                                [item["node"] for item in records], settings["name"])
    for record in records:
        panel = {"id": record["instance"], "digest": digest, "title": settings["name"], "targets": [record["node"]]}
        record["panel"] = panel
        record["workspace"] = checked(client.put(f"/api/v1/workspaces/{record['workspace']['id']}",
            headers=record["headers"], json={"name": record["workspace"]["name"], "revision": 0, "instances": [panel]}))
        if kind != "status":
            record["receipt"] = retained_receipt(service, record, kind, digest)
    activate(client, install_pack(client, material))
    return records


def host(service, kind):
    return service.administration if kind == "admin" else service.containers


def retained_receipt(service, record, kind, digest):
    """Persist a synthetic completed result through the production record validators."""
    spec, intent = (admin_spec, admin_intent) if kind == "admin" else (container_spec, container_intent)
    profile = {"id": secrets.token_hex(16), "node_id": record["node"], "identity": node_identity(record["saved"]),
               "binding": spec.digest({"node": record["node"]}), "version": "synthetic", "account_uid": 1000,
               "revision": 1, "enabled": True}
    pointer = {"id": spec.digest({"instance": record["instance"]}), "name": "example.service"}
    expected = {"resource": pointer, "state": "inactive", "revision": "a" * 64, "definition": "b" * 64}
    if kind == "admin":
        profile.update(provider="systemd", manager="user", system_id=spec.digest({"system": record["node"]}))
        pointer["kind"] = "service"
        expected.update(boot_id=secrets.token_hex(16), invocation="")
        observed = {"state": "active", "boot_id": expected["boot_id"], "invocation": secrets.token_hex(16)}
    else:
        profile.update(provider="docker", connection="rootless", context="", namespace="")
        pointer.update(kind="container", name="example-container", namespace="")
        expected.update(state="exited", replicas=None)
        observed = {"state": "running", "replicas": None, "ready": None}
    owner = host(service, kind)
    owner.records.save_profile(profile)
    now = time.time()
    value = {"id": secrets.token_hex(16), "actor": record["actor"].id, "key": secrets.token_hex(16),
             "package_digest": digest, "instance_id": record["instance"], "action": "start",
             "preview_id": secrets.token_hex(16), "controller": owner.controller,
             "created_at": now, "updated_at": now,
             "targets": [{"node_id": record["node"], "profile": profile,
                          "resource_id": spec.resource(profile["id"], pointer), "expected": expected,
                          "state": "observed", "observed": observed, "observed_at": now}]}
    if kind == "containers":
        value["replicas"] = None
    value["digest"] = spec.digest(intent(value))
    owner.records.insert(value)
    return value


def action_guard(service, record, kind, targets=None):
    """Use current host and installed-policy authority without a module handshake."""
    selected = [record["node"]] if targets is None else targets
    action = "load" if kind == "status" else "preview-start"

    def check():
        actor = service.auth.current(record["actor"].id)
        panel = service.auth.resources.module_instance(actor, record["workspace"]["id"], record["instance"])
        require_action(service, actor, record["workspace"]["id"], panel, action, selected)
    return check


def status_read(client, service, record, targets=None):
    """Read real host broker output from saved synthetic samples, with its live guard."""
    call = BrokerCall(secrets.token_hex(16), secrets.token_hex(16), "system.resources.read",
                      tuple([record["node"]] if targets is None else targets), {}, record["panel"]["digest"],
                      "load", ("system:read",), action_guard(service, record, "status", targets))
    return client.portal.call(handler(service, record["actor"].id, record["instance"]), call)


def history(client, record, kind, status=200):
    return checked(client.post(f"/api/v1/module-{kind}/history", headers=record["headers"],
                               json=context(record)), status)
