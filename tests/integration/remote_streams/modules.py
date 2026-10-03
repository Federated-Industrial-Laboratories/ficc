# SPDX-License-Identifier: Apache-2.0
"""Install the supplied VM package and bind it to a real project display."""

import runpy
import secrets

from .workflows import request


def install(lab, workspace):
    builder = runpy.run_path(str(lab.host / "tools/build-modules.py"))
    manifest, files = builder["read_source"](lab.host / "modules/libvirt")
    files["ficc_module.py"] = (lab.host / "sdk/python/ficc_module.py").read_bytes()
    archive = builder["build_archive"](manifest, files)
    preview = lab.api("POST", "/api/v1/module-install-previews", content=archive,
                      headers={"Content-Type": "application/octet-stream"})
    installed = lab.api("POST", "/api/v1/modules", json={"preview_id": preview["preview_id"],
        "digest": preview["digest"], "accept_unverified": True})
    digest = installed["digest"]
    lab.api("POST", f"/api/v1/modules/{digest}/activation", json={"enabled": True,
        "grants": [{"capability": "workspace:read", "target_ids": [workspace["id"]]},
                   {"capability": "vm:read", "target_ids": [lab.node["id"]]},
                   {"capability": "vm:console", "target_ids": [lab.node["id"]]}]})
    return digest


async def prepare(lab, client):
    workspace = await request(client, "POST", "/api/v1/workspaces", json={"name": "Remote VM operations"})
    digest = install(lab, workspace)
    instance = secrets.token_hex(16)
    workspace = await request(client, "PUT", "/api/v1/workspaces/" + workspace["id"], json={
        "revision": workspace["revision"], "name": workspace["name"], "instances": [{"id": instance,
            "digest": digest, "title": "Remote virtual machine", "targets": [lab.node["id"]]}]})
    return {"workspace_id": workspace["id"], "instance_id": instance, "targets": [lab.node["id"]]}


async def invoke(client, context, action, parameters=None):
    value = await request(client, "POST", "/api/v1/module-invocations", json={
        **context, "action": action, "parameters": parameters or {}})
    result = value["results"]
    assert len(result) == 1 and "error" not in result[0], "The supplied VM action failed."
    return result[0]["data"]


async def reference(lab, client, context):
    inventory = await invoke(client, context, "load")
    assert not inventory["notice"] and len(inventory["rows"]) == 1
    vm_id = inventory["rows"][0]["id"]
    assert vm_id == f"libvirt-{lab.profile['id']}-{lab.display.uuid}"
    result = await invoke(client, context, "open-console", {"vm_ids": [vm_id]})
    assert len(result["viewer_ref"]) == 32
    return result["viewer_ref"]
