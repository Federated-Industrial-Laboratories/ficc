# SPDX-License-Identifier: Apache-2.0
"""Check provider admission, endpoint scopes and credential-free recovery through the host API."""

import json

import pytest
from test_module_adapter_manifest import adapter_package
from test_module_adapters import Transport
from test_module_windows import endpoint
from test_modules_packages import bundle

from ficc.backup import export, restore
from ficc.backup_adapters import validate_records
from ficc.errors import Failure
from ficc.modules import inspect_archive
from ficc.service import Service
from ficc.settings import Settings


def installed(service, count):
    values = [endpoint(index + 1) for index in range(count)]
    for value in values:
        service.windows.records.save(value)
    manifest, files = adapter_package()
    manifest["adapter"].update(execution="controller", transport="winrm-jea", consistency="checked-before-dispatch")
    package = inspect_archive(bundle(manifest, files))
    service.modules.install(package, package.digest)
    transport = Transport()
    transport.endpoint = lambda kind, identity: {key: service.windows.endpoint(identity)[key]
        for key in ("id", "revision", "enabled", "machine_identity")}
    service.adapters.transport = transport
    return values, package.digest


@pytest.mark.parametrize("count", [1, 64])
def test_exact_profile_grants_use_separate_route_and_cannot_be_panels(console, count):
    client, service = console
    endpoints, checksum = installed(service, count)
    profiles = []
    for value in endpoints:
        result = client.post("/api/v1/adapter-profiles", json={"digest": checksum,
            "endpoint_kind": "windows", "endpoint_id": value["id"], "transport_binding_id": value["id"]})
        assert result.status_code == 201, result.text
        profile = result.json()
        profiles.append(profile)
        assert not profile["enabled"] and not profile["admin_granted"]
        assert client.post(f"/api/v1/modules/{checksum}/activation", json={"enabled": True,
            "grants": [{"capability": "provider:admin", "target_ids": [profile["id"]]}]}).status_code == 409
        assert client.post(f"/api/v1/adapter-profiles/{profile['id']}/grant", json={
            "expected_revision": profile["revision"], "confirm": False}).status_code == 422
        enabled = client.post(f"/api/v1/adapter-profiles/{profile['id']}/grant", json={
            "expected_revision": profile["revision"], "confirm": True})
        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["consistency"] == "checked-before-dispatch"
    assert service.modules.get(checksum)["grants"] == [{"capability": "provider:admin",
        "target_ids": sorted(value["id"] for value in profiles)}]
    assert client.delete(f"/api/v1/modules/{checksum}").status_code == 409
    workspace = service.workspaces.create("Provider account boundary")
    response = client.put(f"/api/v1/workspaces/{workspace['id']}", json={"name": workspace["name"],
        "revision": 0, "instances": [{"id": "f" * 32, "digest": checksum, "title": "Cannot render", "targets": [endpoints[0]["id"]]}]})
    assert response.status_code == 409 and response.json()["error"]["code"] == "module_role_invalid"
    assert client.post(f"/api/v1/modules/{checksum}/activation", json={"enabled": False, "grants": []}).status_code == 200
    assert not service.modules.get(checksum)["enabled"]
    for value in profiles:
        assert client.request("DELETE", f"/api/v1/adapter-profiles/{value['id']}", json={"confirm": True}).status_code == 200
    assert client.delete(f"/api/v1/modules/{checksum}").status_code == 200


@pytest.mark.parametrize("count", [1, 64])
def test_windows_endpoint_ids_are_scoped_without_linux_node_access(console, count):
    client, service = console
    endpoints, checksum = installed(service, count)
    allowed = endpoints[-1]
    token, principal = service.auth.issue("token", "Windows operator", ["nodes:read", "vm:read", "providers:write"], [allowed["id"]])
    headers = {"Authorization": "Bearer " + token}
    listed = client.get("/api/v1/windows-endpoints", headers=headers)
    assert listed.status_code == 200 and [item["id"] for item in listed.json()["endpoints"]] == [allowed["id"]]
    assert client.get(f"/api/v1/nodes/{allowed['id']}", headers=headers).status_code == 404
    created = client.post("/api/v1/adapter-profiles", headers=headers, json={"digest": checksum,
        "endpoint_kind": "windows", "endpoint_id": allowed["id"], "transport_binding_id": allowed["id"]})
    assert created.status_code == 201
    denied = endpoints[0]["id"] if count > 1 else "e" * 32
    assert client.post("/api/v1/adapter-profiles", headers=headers, json={"digest": checksum,
        "endpoint_kind": "windows", "endpoint_id": denied, "transport_binding_id": denied}).status_code == 403
    assert client.post(f"/api/v1/windows-endpoints/{allowed['id']}/activation", headers=headers,
        json={"expected_revision": 1, "enabled": False}).status_code == 403
    service.auth.revoke(principal.id)
    assert client.get("/api/v1/windows-endpoints", headers=headers).status_code == 401


def test_invalid_endpoint_enrollment_never_returns_submitted_secrets(console):
    client, service = console
    value = endpoint(1)
    data = {key: value[key] for key in ("name", "host", "port", "configuration", "commands", "certificate_sha256")}
    data.update(enabled=False, credentials={"username": "owner", "password": "PRIVATE-INPUT-MARKER", "domain": ""},
                ca_pem="-----BEGIN CERTIFICATE-----\nPRIVATE-CA-MARKER\n-----END CERTIFICATE-----")
    response = client.post("/api/v1/windows-endpoints", json=data)
    assert response.status_code == 422
    assert "PRIVATE-" not in response.text
    assert service.windows.records.all() == [] and list(service.windows.private.path.iterdir()) == []


@pytest.mark.parametrize("count", [1, 64])
def test_restored_bindings_are_disabled_and_private_accounts_are_excluded(tmp_path, count):
    state, archive, target = (tmp_path / name for name in ("state", "backup", "restored"))
    service = Service(Settings(state_dir=state, control=False))
    endpoints, checksum = installed(service, count)
    profiles = []
    for index, value in enumerate(endpoints):
        account = {"username": f"operator-{index}", "password": f"PRIVATE-ACCOUNT-{index:04d}", "domain": ""}
        ref = service.windows.private.write("credentials", account)
        service.windows.records.save({**value, "credential_ref": ref, "revision": 2}, 1)
        profile = {"id": f"{index + 128:032x}", "digest": checksum, "endpoint_kind": "windows",
            "endpoint_id": value["id"], "endpoint_revision": 2, "machine_identity": value["machine_identity"],
            "transport_binding_id": value["id"], "consistency": "checked-before-dispatch", "revision": 1, "enabled": True}
        service.adapters.records.save_profile(profile)
        profiles.append(profile)
    service.modules.set_enabled(checksum, True, [{"capability": "provider:admin",
        "target_ids": [value["id"] for value in profiles]}], sandbox_ready=True)
    service.close()
    assert export(state, archive)["schema"] == 6
    for path in archive.rglob("*"):
        assert "windows-private" not in path.parts
        if path.is_file():
            assert b"PRIVATE-ACCOUNT-" not in path.read_bytes()
    assert restore(archive, target, True)["module_grants_removed"]
    recovered = Service(Settings(state_dir=target, control=False))
    try:
        assert not recovered.modules.get(checksum)["enabled"] and recovered.modules.get(checksum)["grants"] == []
        for profile in profiles:
            current = recovered.adapters.records.profile(profile["id"])
            assert current["revision"] == 2 and current["enabled"] is False
            endpoint_value = recovered.windows.public(recovered.windows.endpoint(profile["endpoint_id"]))
            assert endpoint_value["revision"] == 3 and endpoint_value["enabled"] is False
            assert not endpoint_value["credentials_ready"]
            with pytest.raises(Failure):
                recovered.adapters.profile(profile["id"])
    finally:
        recovered.close()


@pytest.mark.parametrize("change", ["endpoint-kind", "consistency", "grant-digest", "panel"])
def test_backup_refuses_cross_role_or_rebound_adapter_authority(console, change):
    _, service = console
    endpoints, checksum = installed(service, 1)
    value = endpoints[0]
    profile = {"id": "c" * 32, "digest": checksum, "endpoint_kind": "windows", "endpoint_id": value["id"],
        "endpoint_revision": 1, "machine_identity": value["machine_identity"], "transport_binding_id": value["id"],
        "consistency": "checked-before-dispatch", "revision": 1, "enabled": False}
    service.adapters.records.save_profile(profile)
    if change in {"endpoint-kind", "consistency"}:
        profile["endpoint_kind" if change == "endpoint-kind" else "consistency"] = "linux-ssh" if change == "endpoint-kind" else "provider-lock"
        service.store.db.execute("UPDATE module_adapter_profiles SET value=?", (json.dumps(profile),))
    elif change == "grant-digest":
        service.store.db.execute("INSERT INTO module_grants VALUES (?,?,?)", ("b" * 64, "provider:admin", profile["id"]))
    else:
        workspace = service.workspaces.create("Invalid adapter panel")
        workspace["instances"] = [{"id": "d" * 32, "digest": checksum, "title": "Invalid", "targets": [value["id"]], "state": {}}]
        service.store.db.execute("UPDATE workspaces SET value=? WHERE id=?", (json.dumps(workspace), workspace["id"]))
    with pytest.raises(ValueError):
        validate_records(service.store.db)
