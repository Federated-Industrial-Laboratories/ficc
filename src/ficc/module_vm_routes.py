# SPDX-License-Identifier: Apache-2.0
"""Expose host-confirmed VM requests with current workspace and system authority."""

from typing import Annotated, Literal

from fastapi import Request
from pydantic import Field

from .errors import Failure
from .module_activity import history
from .schema import Model
from .workspace_schema import Identity


class Profile(Model):
    connection: Literal["system", "session"]
    enabled: bool = True


class ProxmoxProfile(Model):
    enabled: bool = True


class Context(Model):
    workspace_id: Identity
    instance_id: Identity


class Preview(Context):
    preview_id: Identity


class Commit(Preview):
    confirm: Literal[True]


class Operation(Context):
    operation_id: Identity


class Resolution(Operation):
    vm_ids: Annotated[list[Annotated[str, Field(min_length=1, max_length=73)]], Field(min_length=1, max_length=64)]
    confirm: Literal[True]


class Removal(Operation):
    confirm: Literal[True]
    acknowledge_orphans: bool = False


def instance_guard(service, actor, context, value):
    def check():
        caller = service.auth.current(actor)
        instance = service.auth.resources.module_operation(caller, context.workspace_id, context.instance_id, value)
        service.modules.require(instance["digest"], "workspace:read", [context.workspace_id])
        service.policies.check_many(caller, [("modules:execute", None, None), ("workspaces:read", None, None),
                                            *[("nodes:read", item["node_id"], None) for item in value["targets"]]])
    check()
    return check


def install(app, service, principal):
    vms = service.vms
    providers = service.vm_providers

    def actor(request, scope):
        value = principal(request, scope)
        if value.root_ids is not None:
            raise Failure("denied", "A folder-restricted credential cannot manage VMs.", 403)
        return value.id

    @app.get("/api/v1/vm-profiles")
    async def profiles(request: Request):
        return {"profiles": vms.profiles(actor(request, "vm:read"))}

    @app.put("/api/v1/nodes/{node_id}/vm-profile")
    async def profile(node_id: str, body: Profile, request: Request):
        owner = principal(request, "nodes:write", node_id).id
        return vms.set_profile(owner, node_id, body.connection, body.enabled)

    @app.get("/api/v1/proxmox-profiles")
    async def proxmox_profiles(request: Request):
        return {"profiles": service.proxmox.profiles(actor(request, "vm:read"))}

    @app.put("/api/v1/nodes/{node_id}/proxmox-profile")
    async def proxmox_profile(node_id: str, body: ProxmoxProfile, request: Request):
        owner = principal(request, "nodes:write", node_id).id
        return await service.proxmox.set_profile(owner, node_id, body.enabled)

    @app.delete("/api/v1/nodes/{node_id}/proxmox-profile")
    async def remove_proxmox_profile(node_id: str, request: Request):
        owner = principal(request, "nodes:write", node_id).id
        return await service.proxmox.remove_profile(owner, node_id)

    @app.post("/api/v1/module-vms/preview")
    async def preview(body: Preview, request: Request):
        owner = actor(request, "vm:power")
        host, value = providers.preview(owner, body.preview_id)
        return host.preview_for_confirmation(owner, body.preview_id, instance_guard(service, owner, body, value))

    @app.post("/api/v1/module-vms/commit")
    async def commit(body: Commit, request: Request):
        owner = actor(request, "vm:power")
        key = request.headers.get("idempotency-key")
        async with providers.admission:
            host, value = providers.existing(owner, key) or providers.preview(owner, body.preview_id)
            check = instance_guard(service, owner, body, value)
            return await host.commit(owner, body.preview_id, key, check)

    @app.post("/api/v1/module-vms/operation")
    async def operation(body: Operation, request: Request):
        owner = actor(request, "vm:read")
        host, value = providers.operation(body.operation_id)
        return await host.operation(owner, body.operation_id, instance_guard(service, owner, body, value))

    @app.post("/api/v1/module-vms/resolve")
    async def resolve(body: Resolution, request: Request):
        owner = actor(request, "vm:power")
        host, value = providers.operation(body.operation_id)
        return await host.resolve(owner, body.operation_id, body.vm_ids, instance_guard(service, owner, body, value))

    @app.delete("/api/v1/nodes/{node_id}/vm-profile")
    async def remove_profile(node_id: str, request: Request):
        owner = principal(request, "nodes:write", node_id).id
        return await vms.remove_profile(owner, node_id)

    @app.post("/api/v1/module-vms/history")
    async def all_operations(body: Context, request: Request):
        owner = actor(request, "vm:read")
        values = [operation for host in providers.hosts.values()
                  for operation in history(service, host, owner, body, "vm:read", instance_guard)["operations"]]
        return {"operations": sorted(values, key=lambda item: item["created_at"], reverse=True)}

    @app.post("/api/v1/module-vms/forget")
    async def forget(body: Removal, request: Request):
        owner = actor(request, "vm:power")
        host, value = providers.operation(body.operation_id)
        return await host.forget(owner, body.operation_id, instance_guard(service, owner, body, value),
                                 acknowledge_orphans=body.acknowledge_orphans)
