# SPDX-License-Identifier: Apache-2.0
"""Serve constrained module reads without disclosing transport credentials."""

from .errors import Failure
from .modules.validation import fields

PRIMITIVES = {"system.resources.read": "system:read"}


def handler(service, actor, instance_id=None):
    async def dispatch(call):
        if call.primitive.startswith("vm.") and instance_id is not None:
            parts = call.primitive.split(".")
            if len(parts) == 3 and parts[1] in service.vm_providers.hosts:
                if parts[2] == "console":
                    return await service.viewers.issue(actor, call, instance_id, provider=parts[1])
                return await service.vm_providers.adapter(parts[1]).broker(actor, call, instance_id)
        if call.primitive.startswith("container.") and instance_id is not None:
            return await service.containers.broker(actor, call, instance_id)
        if call.primitive.startswith("admin.") and instance_id is not None:
            return await service.administration.broker(actor, call, instance_id)
        capability = PRIMITIVES.get(call.primitive)
        if capability is None or capability not in call.action_capabilities:
            raise Failure("module_primitive_denied", "The requested module primitive is not permitted.", 403)
        fields(call.parameters, set())
        results = []
        for target in call.target_ids:
            try:
                call.check()
                service.modules.require(call.package_digest, capability, [target])
                service.authorize(actor, "nodes:read", target)
                service.authorize(actor, "resources:read", target)
                node = service.view(service.store.node(target))
                data = {key: node[key] for key in ("id", "name", "state", "resources", "last_seen", "stale", "error")}
                call.check()
                results.append({"target": target, "data": data})
            except Failure as exc:
                results.append({"target": target, "error": {"code": exc.code, "message": exc.message}})
        call.check()
        return results
    return dispatch
