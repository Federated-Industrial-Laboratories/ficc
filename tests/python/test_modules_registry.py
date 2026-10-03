# SPDX-License-Identifier: Apache-2.0
"""Exercise digest-specific authority, rollback, revocation and bounded storage."""

import pytest
from test_modules_packages import bundle, package

from ficc.errors import Failure
from ficc.modules import Registry, inspect_archive
from ficc.store import Store


@pytest.fixture
def registry(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    result = Registry(store, tmp_path / "modules")
    yield result
    store.close()


def install(registry, **changes):
    inspection = inspect_archive(bundle(*package(**changes)))
    return registry.install(inspection, inspection.digest)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_exact_grants_revocation_and_version_rollback(registry, count):
    target_ids = [f"workspace-{i}" for i in range(count)]
    grants = [{"capability": "workspace:read", "target_ids": target_ids}]
    first = install(registry, capabilities=["workspace:read"])
    first_id = first["digest"]
    assert not first["enabled"] and first["grants"] == []
    with pytest.raises(Failure):
        registry.set_enabled(first_id, True, [])
    first = registry.set_enabled(first_id, True, grants)
    registry.require(first_id, "workspace:read", target_ids)
    with pytest.raises(Failure):
        registry.require(first_id, "workspace:read", ["ungranted"])
    second = install(registry, version="2.0.0", capabilities=["workspace:read"])
    second_id = second["digest"]
    assert not second["enabled"] and second["grants"] == []
    registry.set_enabled(second_id, True, grants)
    assert not registry.get(first_id)["enabled"]
    assert not registry.get(first_id)["grants"]
    with pytest.raises(Failure):
        registry.check(first_id, first["revision"])
    registry.set_enabled(first_id, True, grants)
    assert not registry.get(second_id)["enabled"]
    assert any(row["previous_digest"] == second_id and row["new_digest"] == first_id
               for row in registry.history("org.example.demo"))
    registry.revoke(first_id)
    with pytest.raises(Failure):
        registry.require(first_id, "workspace:read", target_ids)


def test_install_digest_and_external_capabilities_fail_closed(registry):
    inspection = inspect_archive(bundle(*package(capabilities=["unavailable:action"])))
    with pytest.raises(Failure):
        registry.install(inspection, "0" * 64)
    assert registry.list() == []
    registry.install(inspection, inspection.digest)
    with pytest.raises(Failure) as error:
        registry.set_enabled(inspection.digest, True,
                             [{"capability": "unavailable:action", "target_ids": ["system-a"]}],
                             sandbox_ready=True)
    assert error.value.code == "module_capability_unavailable"
    assert not registry.get(inspection.digest)["enabled"]


def test_uninstall_revokes_before_refusing_active_lease(registry):
    installed = install(registry)
    digest = installed["digest"]
    registry.set_enabled(digest, True, [])
    current = registry.acquire(digest)
    with pytest.raises(Failure) as error:
        registry.uninstall(digest)
    assert error.value.code == "module_busy"
    with pytest.raises(Failure):
        registry.check(digest, current["revision"])
    registry.release(digest)
    registry.uninstall(digest)
    assert registry.list() == []
    assert not (registry.root / digest).exists()


def test_package_storage_history_and_grants_are_bounded(registry, monkeypatch):
    import ficc.modules.registry as module

    first = install(registry)
    monkeypatch.setattr(module, "MAX_PACKAGES", 1)
    with pytest.raises(Failure):
        install(registry, version="2.0.0")
    monkeypatch.setattr(module, "MAX_PACKAGES", 64)
    monkeypatch.setattr(module, "MAX_STORAGE", 1)
    with pytest.raises(Failure):
        install(registry, version="2.0.0")
    monkeypatch.setattr(module, "MAX_HISTORY", 2)
    for _ in range(4):
        registry.revoke(first["digest"])
    assert len(registry.history("org.example.demo")) == 2
    monkeypatch.setattr(module, "MAX_STORAGE", 128 * 1024 * 1024)
    grantable = install(registry, version="3.0.0", capabilities=["workspace:write"])
    monkeypatch.setattr(module, "MAX_GRANTS", 1)
    with pytest.raises(Failure):
        registry.set_enabled(grantable["digest"], True,
                             [{"capability": "workspace:write", "target_ids": ["a", "b"]}])
    assert not registry.get(grantable["digest"])["enabled"]
    assert not registry.get(grantable["digest"])["grants"]


def test_executable_activation_requires_trusted_readiness(registry):
    runtime = {"kind": "python", "language": "python", "platform": "linux",
               "architecture": "any", "entry": "main.py"}
    inspection = inspect_archive(bundle(*package({"main.py": b"pass"}, runtime=runtime)))
    registry.install(inspection, inspection.digest)
    with pytest.raises(Failure) as error:
        registry.set_enabled(inspection.digest, True, [])
    assert error.value.code == "module_sandbox_unavailable"
    assert registry.set_enabled(inspection.digest, True, [], sandbox_ready=True)["enabled"]
