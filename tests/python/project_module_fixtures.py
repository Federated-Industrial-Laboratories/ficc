# SPDX-License-Identifier: Apache-2.0
"""Run real module and policy authority with an explicit synthetic VM provider."""

import asyncio
import contextlib
import contextvars
import hashlib
import json
import secrets
from pathlib import Path

from conftest import node
from fastapi.testclient import TestClient
from ficc_node import vm_rpc, vm_spec, vm_state
from policy_fixtures import activate, install_pack
from resource_fixtures import assign
from test_identity_projects import member
from test_module_vm import FakeProvider
from test_modules_packages import bundle

from ficc.api import create_app
from ficc.jobs import Jobs
from ficc.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
VM_SCOPES = ["nodes:read", "resources:read", "workspaces:read", "workspaces:write",
             "modules:read", "modules:execute", "vm:read", "vm:power", "vm:console"]


def checked(response, status=200):
    assert response.status_code == status, response.text
    return response.json()


@contextlib.contextmanager
def console(state, monkeypatch):
    async def idle(self):
        await asyncio.Event().wait()
    monkeypatch.setattr(Jobs, "poll", idle)
    app = create_app(Settings(state_dir=state, control=False, poll_interval=3600, stale_after=7200))
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        service = app.state.service
        secret, _ = service.auth.issue("bootstrap", lifetime=60)
        response = checked(client.post("/api/v1/session", json={"bootstrap": secret},
                           headers={"Origin": service.settings.origin}))
        client.headers.update({"Origin": service.settings.origin, "X-CSRF-Token": response["csrf"]})
        yield client, service


def installed(client, spaces, nodes, name="libvirt"):
    source = ROOT / "modules" / name
    manifest = json.loads((source / "manifest.json").read_text())
    files = {"main.py": (source / "payload/main.py").read_bytes(),
             "ficc_module.py": (ROOT / "sdk/python/ficc_module.py").read_bytes()}
    manifest["files"] = {key: hashlib.sha256(value).hexdigest() for key, value in files.items()}
    preview = checked(client.post("/api/v1/module-install-previews", content=bundle(manifest, files),
                                  headers={"Content-Type": "application/octet-stream"}))
    digest = preview["digest"]
    checked(client.post("/api/v1/modules", json={"preview_id": preview["preview_id"], "digest": digest,
                                                "accept_unverified": True}), 201)
    grants = [{"capability": cap, "target_ids": spaces if cap == "workspace:read" else nodes}
              for cap in manifest["capabilities"]]
    checked(client.post(f"/api/v1/modules/{digest}/activation", json={"enabled": True, "grants": grants}))
    return digest, grants


def prepare(client, service, material, count):
    records = []
    for index in range(max(2, count)):
        user, project, principal, headers = member(service, f"VM member {index}", scopes=VM_SCOPES)
        identity = f"{index + 100:032x}"
        service.store.save_node({**node(index), "id": identity})
        assign(client, project, [identity])
        profile = checked(client.put(f"/api/v1/nodes/{identity}/vm-profile", json={"connection": "session"}))
        workspace = checked(client.post("/api/v1/workspaces", headers=headers, json={"name": f"VM project {index}"}), 201)
        checked(client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}",
                           json={"revision": 0, "roles": ["vm-operator"]}))
        records.append({"user": user, "project": project, "actor": principal, "headers": headers,
                        "node": identity, "profile": profile, "workspace": workspace,
                        "instance": secrets.token_hex(16), "vm": f"libvirt-{profile['id']}-{'0' * 32}"})
    digest, grants = installed(client, [item["workspace"]["id"] for item in records], [item["node"] for item in records])
    for item in records:
        panel = {"id": item["instance"], "digest": digest, "title": "VMs", "targets": [item["node"]]}
        item["panel"] = panel
        item["workspace"] = checked(client.put(f"/api/v1/workspaces/{item['workspace']['id']}", headers=item["headers"],
            json={"name": item["workspace"]["name"], "revision": 0, "instances": [panel]}))
    activate(client, install_pack(client, material))
    return records, digest, grants


def transport(service, monkeypatch, tmp_path, records, providers=None):
    providers = providers or {item["node"]: FakeProvider(1) for item in records}
    current = contextvars.ContextVar("synthetic_vm_node")
    for identity in providers:
        (tmp_path / identity).mkdir(mode=0o700, parents=True, exist_ok=True)
    monkeypatch.setattr(vm_rpc, "Libvirt", lambda *_args, **_kwargs: providers[current.get()])
    monkeypatch.setattr(vm_state, "root", lambda: tmp_path / current.get())

    async def command(system, _command, payload, check, timeout):
        check()
        token = current.set(system["id"])
        try:
            result = vm_rpc.dispatch(vm_spec.decode(payload))
        finally:
            current.reset(token)
        check()
        return 0, vm_spec.encode({"version": 1, "data": result}), b""
    monkeypatch.setattr(service.ssh, "command", command)
    return providers


def context(record):
    return {"workspace_id": record["workspace"]["id"], "instance_id": record["instance"]}


def invoke(client, record, action="load", parameters=None, status=200):
    return checked(client.post("/api/v1/module-invocations", headers=record["headers"], json={
        **context(record), "targets": [record["node"]], "action": action, "parameters": parameters or {}}), status)


def bind_role(client, record, roles, revision):
    return checked(client.put(f"/api/v1/projects/{record['project']['id']}/policy-roles/{record['user']['id']}",
                              json={"roles": roles, "revision": revision}))
