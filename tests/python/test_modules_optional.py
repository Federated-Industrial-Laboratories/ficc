# SPDX-License-Identifier: Apache-2.0
"""Keep optional module permissions absent until explicit current grants exist."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_modules_packages import bundle, package
from test_modules_registry import registry as registry

from ficc.backup_modules import records
from ficc.errors import Failure
from ficc.module_capabilities import validate_instance
from ficc.modules import inspect_archive
from ficc.modules.manifest import required_capabilities, validate_manifest
from ficc.modules.runtime import Runtime
from ficc.workspace_schema import Instance

ROOT = Path(__file__).resolve().parents[2]


def install(registry, files=None, **changes):
    value = inspect_archive(bundle(*package(files, **changes)))
    registry.install(value, value.digest)
    return value.digest


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_optional_grants_do_not_block_required_targets_or_grant_access(registry, count):
    selected = [f"{index:032x}" for index in range(count)]
    digest = install(registry, capabilities=["system:read", "files:read"], optional_capabilities=["files:read"])
    grants = [{"capability": "system:read", "target_ids": selected}]
    registry.set_enabled(digest, True, grants)
    registry.require(digest, "system:read", selected)
    with pytest.raises(Failure, match="does not permit"):
        registry.require(digest, "files:read", selected)
    store = SimpleNamespace(node=lambda target: {"id": target})
    service = SimpleNamespace(modules=registry, store=store)
    validate_instance(service, "workspace", Instance(id="a" * 32, digest=digest, title="Read", targets=selected))
    registry.set_enabled(digest, True, grants + [{"capability": "files:read", "target_ids": selected[:1]}])
    registry.require(digest, "files:read", selected[:1])
    if count == 64:
        with pytest.raises(Failure):
            registry.require(digest, "files:read", selected)
    revision = registry.get(digest)["revision"]
    registry.set_enabled(digest, True, grants)
    with pytest.raises(Failure):
        registry.check(digest, revision)
    validate_instance(service, "workspace", Instance(id="a" * 32, digest=digest, title="Read", targets=selected))


def test_legacy_manifest_keeps_every_declared_capability_required(registry):
    digest = install(registry, capabilities=["system:read", "files:read"])
    manifest = registry.get(digest)["manifest"]
    assert "optional_capabilities" not in manifest
    assert required_capabilities(manifest) == manifest["capabilities"]
    with pytest.raises(Failure, match="Every requested"):
        registry.set_enabled(digest, True, [{"capability": "system:read", "target_ids": ["system"]}])


@pytest.mark.parametrize("optional", [["undeclared:read"], ["system:read", "system:read"], "system:read", None, [42]])
def test_optional_declaration_must_be_unique_declared_capabilities(optional):
    manifest, _ = package(capabilities=["system:read"], optional_capabilities=optional)
    with pytest.raises(Failure):
        validate_manifest(manifest)


def test_unavailable_optional_permission_can_remain_absent_but_cannot_be_granted(registry):
    digest = install(registry, capabilities=["system:read", "unavailable:action"],
                     optional_capabilities=["unavailable:action"])
    grants = [{"capability": "system:read", "target_ids": ["system"]}]
    registry.set_enabled(digest, True, grants)
    with pytest.raises(Failure) as error:
        registry.set_enabled(digest, True, grants + [{"capability": "unavailable:action", "target_ids": ["system"]}])
    assert error.value.code == "module_capability_unavailable"
    assert registry.get(digest)["grants"] == grants


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_optional_action_refused_before_sandbox_or_callback(registry, count):
    selected = [f"{index:032x}" for index in range(count)]
    runtime = {"kind": "python", "language": "python", "entry": "main.py", "platform": "linux",
               "architecture": "any", "protocol": 2}
    digest = install(registry, files={"main.py": b"raise SystemExit(1)\n"},
        capabilities=["system:read", "files:read"], optional_capabilities=["files:read"],
        runtime=runtime, actions=[{"id": "read-files", "parameters": {}, "capabilities": ["files:read"]}])
    registry.set_enabled(digest, True, [{"capability": "system:read", "target_ids": selected}], sandbox_ready=True)
    host = Runtime(registry)

    async def forbidden(*args):
        pytest.fail("An ungranted optional action reached execution.")
    host.sandbox.probe = forbidden
    with pytest.raises(Failure, match="does not permit"):
        await host.invoke(digest, "read-files", selected, {}, lambda: None, broker=forbidden)
    assert not host.active and not registry._leases


def test_optional_only_instance_targets_must_still_have_actual_grants(registry):
    digest = install(registry, capabilities=["system:read"], optional_capabilities=["system:read"])
    registry.set_enabled(digest, True, [])
    service = SimpleNamespace(modules=registry, store=SimpleNamespace(node=lambda _: None))
    empty = Instance(id="a" * 32, digest=digest, title="Optional", targets=[])
    validate_instance(service, "workspace", empty)
    selected = empty.model_copy(update={"targets": ["1" * 32]})
    with pytest.raises(Failure, match="no current optional"):
        validate_instance(service, "workspace", selected)
    registry.set_enabled(digest, True, [{"capability": "system:read", "target_ids": ["1" * 32]}])
    validate_instance(service, "workspace", selected)


def test_backup_accepts_missing_optional_grants_and_refuses_missing_required(registry):
    db = registry.store.db
    digest = install(registry, capabilities=["system:read", "files:read"], optional_capabilities=["files:read"])
    registry.set_enabled(digest, True, [{"capability": "system:read", "target_ids": ["system"]}])
    assert records(db)[digest]["grants"] == {"system:read": ["system"]}
    db.execute("DELETE FROM module_grants")
    with pytest.raises(ValueError, match="invalid"):
        records(db)


def test_supplied_read_workflows_declare_write_and_console_optional():
    for module, optional, required in (("file-editor", ["files:write"], ["workspace:read", "files:read"]),
                                      ("libvirt", ["vm:power", "vm:console"], ["workspace:read", "vm:read"])):
        manifest = json.loads((ROOT / "modules" / module / "manifest.json").read_text())
        assert manifest["optional_capabilities"] == optional
        assert required_capabilities(manifest) == required
        legacy = copy.deepcopy(manifest)
        del legacy["optional_capabilities"]
        assert required_capabilities(legacy) == legacy["capabilities"]


def test_activation_route_preserves_explicit_optional_grants(console):
    client, service = console
    space = service.workspaces.create("Optional grants")
    digest = install(service.modules, capabilities=["workspace:read", "workspace:write"],
                     optional_capabilities=["workspace:write"])
    grants = [{"capability": "workspace:read", "target_ids": [space["id"]]}]
    response = client.post(f"/api/v1/modules/{digest}/activation", json={"enabled": True, "grants": grants})
    assert response.status_code == 200, response.text
    assert response.json()["grants"] == grants
    validate_instance(service, space["id"], Instance(id="a" * 32, digest=digest, title="Read"))
    with pytest.raises(Failure):
        service.modules.require(digest, "workspace:write", [space["id"]])
    response = client.post(f"/api/v1/modules/{digest}/activation", json={"enabled": True, "grants": []})
    assert response.status_code == 400
    assert service.modules.get(digest)["grants"] == grants
