# SPDX-License-Identifier: Apache-2.0
"""Preserve lifecycle recovery authority and list only permitted panel history."""

from .errors import Failure


def require_removable(service, *, instance_id=None, digest=None):
    for host in (*service.vm_providers.hosts.values(), service.containers, service.administration):
        if any((instance_id is None or value["instance_id"] == instance_id)
               and (digest is None or value["package_digest"] == digest) for value in host.records.all()):
            raise Failure("module_history_retained", "Remove operation receipts from this panel's action history before removing or changing it.", 409)


def history(service, host, actor, context, capability, guard):
    service.authorize(actor, "modules:execute")
    service.authorize(actor, "workspaces:read")
    workspace = service.workspaces.scoped(service.auth.current(actor)).get(context.workspace_id)
    instance = next((item for item in workspace["instances"] if item["id"] == context.instance_id), None)
    if instance is None:
        raise Failure("not_found", "The module panel was not found.", 404)
    service.modules.require(instance["digest"], "workspace:read", [context.workspace_id])
    operations = []
    for value in host.records.all():
        if value["instance_id"] != context.instance_id or value["package_digest"] != instance["digest"]:
            continue
        try:
            host.local_authority(actor, value, capability, guard(service, actor, context, value))
        except Failure:
            continue
        public = host.public_operation(value)
        operations.append({key: public[key] for key in ("id", "action", "created_at", "updated_at", "cleanup") if key in public}
                          | {"outcomes": {state: sum(item["state"] == state for item in value["targets"])
                                          for state in sorted({item["state"] for item in value["targets"]})}})
    return {"operations": operations}
