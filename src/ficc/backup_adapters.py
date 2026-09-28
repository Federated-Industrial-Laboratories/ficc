# SPDX-License-Identifier: Apache-2.0
"""Check package roles and exact endpoint types before restoring provider bindings."""

from .errors import Failure
from .module_adapter_store import validate_records as adapter_records
from .module_windows_store import validate_records as windows_records
from .modules.validation import loads


def validate_records(db):
    try:
        validate_bindings(db)
    except (Failure, KeyError, TypeError) as exc:
        raise ValueError("The provider adapter backup records are invalid.") from exc


def validate_bindings(db):
    windows_records(db)
    endpoints = {
        "linux-ssh": {row[0] for row in db.execute("SELECT id FROM nodes")},
        "windows": {row[0] for row in db.execute("SELECT id FROM module_windows_endpoints")},
    }
    if endpoints["linux-ssh"] & endpoints["windows"]:
        raise ValueError("Multiple endpoint types use the same identity.")
    packages = {row[0]: loads(bytes(row[1]), 65536) for row in db.execute("SELECT digest,manifest FROM module_packages")}
    profiles = db.execute("SELECT id,endpoint_id,digest,value FROM module_adapter_profiles").fetchall()
    operations = db.execute("SELECT id,actor,key,digest,value FROM module_adapter_operations").fetchall()
    adapter_records(profiles, operations, endpoints, set(packages))
    profile_values = {}
    for row in profiles:
        value = loads(row[3].encode())
        manifest = packages[value["digest"]]
        profile_values[value["id"]] = value
        if (value["endpoint_id"] not in endpoints[value["endpoint_kind"]]
                or manifest.get("role", "module") != "provider-adapter"):
            raise ValueError("The adapter binding has an invalid endpoint or package role.")
        adapter = manifest["adapter"]
        expected = "linux-ssh" if adapter["execution"] == "enrolled-node" else "windows"
        if expected != value["endpoint_kind"] or value["consistency"] != adapter["consistency"]:
            raise ValueError("The adapter binding differs from its package contract.")
    for checksum, capability, target in db.execute("SELECT digest,capability,target_id FROM module_grants"):
        if capability != "provider:admin":
            continue
        profile = profile_values.get(target)
        if profile is None or profile["digest"] != checksum:
            raise ValueError("The provider grant does not match its exact package and profile.")
    for raw, in db.execute("SELECT value FROM workspaces"):
        for item in loads(raw.encode())["instances"]:
            if packages.get(item["digest"], {}).get("role") == "provider-adapter":
                raise ValueError("Provider adapters cannot be workspace panels.")
