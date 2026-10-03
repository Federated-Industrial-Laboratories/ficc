# SPDX-License-Identifier: Apache-2.0
"""Adapt existing synthetic provider services without changing their denial rules."""

from types import SimpleNamespace


def batched_service(service):
    def check_many(actor, requirements):
        for scope, node, root in requirements:
            assert root is None
            service.authorize(actor, scope, node)

    service.auth = SimpleNamespace(current=lambda actor: actor)
    service.policies = SimpleNamespace(check_many=check_many)
    if not hasattr(service.modules, "require_many"):
        def require_many(digest, requirements):
            for capability, targets in requirements:
                service.modules.require(digest, capability, targets)
        service.modules.require_many = require_many
    return service
