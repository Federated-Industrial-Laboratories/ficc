# SPDX-License-Identifier: Apache-2.0
"""Keep Proxmox task failures and profile pins intact across retained history."""

import copy
import sqlite3
import threading
from types import SimpleNamespace

import pytest
from test_module_proxmox_protocol import identity, provider

from ficc.errors import Failure
from ficc.module_proxmox_store import Records, initialize, intent, operation, spec, validate_records
from ficc.state_provider import BoundConnection


def profile(index=0):
    return {"id": f"{index + 1:032x}", "node_id": f"node-{index}", "connection": "local",
            "identity": "a" * 64, "revision": 1, "enabled": True, "provider": provider()}


def value(size):
    selected = profile()
    targets = [{"node_id": selected["node_id"], "profile": copy.deepcopy(selected),
                "vm_id": f"proxmox-{selected['id']}-{identity(index + 100)}",
                "expected": {"uuid": identity(index + 100), "definition": "f" * 64, "state": "off"},
                "state": "failed", "task": {
                    "upid": f"UPID:fixture:00000001:00000002:00000003:ficcvmstart:{index + 100}:root@pam:",
                    "state": "stopped", "exitstatus": "FICC_PROVIDER_START_FAILED"}} for index in range(size)]
    result = {"id": "b" * 32, "actor": "owner", "key": "proxmox-test-key-0001", "package_digest": "a" * 64,
              "instance_id": "instance", "action": "start", "preview_id": "c" * 32, "controller": "d" * 32,
              "created_at": 1, "updated_at": 2, "targets": targets}
    result["digest"] = spec.digest(intent(result))
    return result


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_exact_failed_task_survives_store_and_backup_validation(size):
    store = SimpleNamespace(db=sqlite3.connect(":memory:", factory=BoundConnection), lock=threading.RLock())
    initialize(store.db)
    records = Records(store)
    records.save_profile(profile())
    original = value(size)
    assert operation(original) == original
    records.insert(original)
    stored = records.get(original["id"])
    assert stored == original
    profiles = list(store.db.execute("SELECT * FROM module_proxmox_profiles"))
    operations = list(store.db.execute("SELECT * FROM module_proxmox_operations"))
    validate_records(profiles, operations, {"node-0"})
    assert records.retained("node-0")
    stored["cleanup"] = []
    records.save(stored)
    operations = list(store.db.execute("SELECT * FROM module_proxmox_operations"))
    with pytest.raises(ValueError, match="unfinished"):
        validate_records(profiles, operations, {"node-0"})
    records.remove(original["id"])
    assert records.retained("node-0")
    records.remove_profile("node-0")
    assert not records.retained("node-0")
    with pytest.raises(Failure):
        records.get(original["id"])


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("mutation", ["missing", "null", "success", "running", "foreign", "provider", "uri", "digest"])
def test_failed_task_and_frozen_intent_reject_tampering(size, mutation):
    record = value(size)
    target = record["targets"][-1]
    if mutation == "missing":
        target.pop("task")
    elif mutation == "null":
        target["task"] = None
    elif mutation == "success":
        target["task"]["exitstatus"] = "OK"
    elif mutation == "running":
        target["task"] = {"upid": target["task"]["upid"], "state": "running"}
    elif mutation == "foreign":
        target["task"]["upid"] = target["task"]["upid"].replace(":fixture:", ":foreign:")
    elif mutation == "provider":
        target["profile"]["provider"]["fingerprint"] = "e" * 64
    elif mutation == "uri":
        target["profile"]["connection"] = "https://other.invalid"
    else:
        target["expected"]["definition"] = "e" * 64
    with pytest.raises(ValueError):
        operation(record)
