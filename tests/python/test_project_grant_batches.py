# SPDX-License-Identifier: Apache-2.0
"""Use real registry state to check complete target batches and later revocation."""

import pytest
from test_modules_registry import install
from test_modules_registry import registry as registry

from ficc.errors import Failure


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_package_grant_batches_keep_exact_targets_and_fresh_state(registry, count):
    nodes = [f"system-{index}" for index in range(max(2, count))]
    module = install(registry, capabilities=["vm:read", "vm:console"], optional_capabilities=["vm:console"])
    digest = module["digest"]
    grants = [{"capability": capability, "target_ids": nodes} for capability in ("vm:read", "vm:console")]
    registry.set_enabled(digest, True, grants)
    requests = [(capability, nodes[:count]) for capability in ("vm:read", "vm:console")]
    assert registry.require_many(digest, requests) is None
    assert registry.require(digest, "vm:read", nodes[:count]) is None
    with pytest.raises(Failure):
        registry.require_many(digest, [*requests, ("vm:console", ["outside"])])
    removed = nodes[count - 1]
    grants[1] = {"capability": "vm:console", "target_ids": [node for node in nodes if node != removed]}
    registry.set_enabled(digest, True, grants)
    with pytest.raises(Failure):
        registry.require_many(digest, requests)
    control = nodes[0 if count > 1 else 1]
    registry.require_many(digest, [("vm:read", [control]), ("vm:console", [control])])
    registry.revoke(digest)
    with pytest.raises(Failure) as denied:
        registry.require_many(digest, requests)
    assert denied.value.code == "module_disabled"
