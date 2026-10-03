# SPDX-License-Identifier: Apache-2.0
"""Keep broad provider admission separate from ordinary module authority."""

import copy

import pytest
from test_modules_packages import bundle, package

from ficc.errors import Failure
from ficc.modules import inspect_archive
from ficc.modules.manifest import validate_manifest


def adapter_package(count=1, **changes):
    files = {f"data-{index}.txt": b"bounded" for index in range(count - 1)}
    files["main.py"] = b"raise SystemExit(0)\n"
    manifest, files = package(files, category="virtual-machines", role="provider-adapter",
        capabilities=["provider:admin"], actions=[], ui={"type": "column", "children": []},
        runtime={"kind": "python", "language": "python", "entry": "main.py", "platform": "linux",
                 "architecture": "any", "protocol": 1},
        adapter={"version": 1, "family": "virtual-machines", "execution": "enrolled-node",
                 "transport": "local-ipc", "consistency": "provider-lock",
                 "operations": ["inventory", "status", "start", "shutdown", "console"]})
    manifest.update(changes)
    return manifest, files


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("windows", [False, True])
def test_exact_adapter_role_survives_inspected_package(count, windows):
    manifest, files = adapter_package(count)
    if windows:
        manifest["adapter"].update(execution="controller", transport="winrm-jea",
                                   consistency="checked-before-dispatch")
    assert inspect_archive(bundle(manifest, files)).manifest == manifest


@pytest.mark.parametrize("field,value", [
    ("role", "module"), ("role", "provider"), ("category", "containers"),
    ("capabilities", ["vm:read"]), ("capabilities", ["provider:admin", "vm:power"]),
    ("optional_capabilities", ["provider:admin"]),
    ("ui", {"type": "column", "children": [{"type": "clock"}]}),
    ("actions", [{"id": "read", "parameters": {}, "capabilities": []}]),
    ("runtime", {"kind": "declarative", "language": "none"}),
])
def test_adapter_cannot_hide_broad_authority_or_render_as_ordinary_module(field, value):
    manifest, _ = adapter_package(**{field: value})
    with pytest.raises(Failure):
        validate_manifest(manifest)


@pytest.mark.parametrize("field,value", [
    ("version", True), ("version", 2), ("execution", "controller"),
    ("transport", "raw-exec"), ("family", "containers"),
    ("consistency", "atomic"), ("consistency", []),
    ("operations", ["inventory"]), ("operations", ["inventory", "status", "shell"]),
    ("operations", ["inventory", "status", "status"]),
])
def test_unknown_contract_or_transport_is_rejected(field, value):
    manifest, _ = adapter_package()
    manifest["adapter"][field] = value
    with pytest.raises(Failure):
        validate_manifest(manifest)


def test_legacy_package_is_unchanged_and_cannot_request_provider_admin():
    manifest, _ = package()
    original = copy.deepcopy(manifest)
    assert validate_manifest(manifest) == original and "role" not in manifest
    manifest["capabilities"] = ["provider:admin"]
    with pytest.raises(Failure):
        validate_manifest(manifest)


def test_adapter_fields_do_not_admit_paths_or_protocol_downgrade():
    manifest, _ = adapter_package()
    manifest["adapter"]["socket"] = "/tmp/provider.sock"
    with pytest.raises(Failure):
        validate_manifest(manifest)
    manifest["adapter"].pop("socket")
    manifest["runtime"]["protocol"] = 2
    with pytest.raises(Failure):
        validate_manifest(manifest)
