# SPDX-License-Identifier: Apache-2.0
"""Keep endpoint bindings, private intents and recovery proof across persistence."""

import copy
import hashlib
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from ficc import module_adapter_store as model
from ficc.errors import Failure
from ficc.modules.validation import dumps


def profile(index=0):
    return {"id": f"{index + 1:032x}", "endpoint_kind": "linux-ssh", "endpoint_id": f"{index + 100:032x}",
        "endpoint_revision": 1, "machine_identity": "a" * 64, "transport_binding_id": "b" * 32,
        "consistency": "provider-lock", "digest": "c" * 64, "revision": 1, "enabled": False}


def operation(count=1):
    binding, targets = profile(), []
    for index in range(count):
        key, birth = f"vm-{index}", "f" * 64
        resource = {"id": model.resource_id(key, birth), "key": key, "birth": birth,
                    "revision": "e" * 64, "state": "off"}
        targets.append({"node_id": binding["endpoint_id"], "profile": copy.deepcopy(binding),
            "vm_id": f"vm-{binding['id']}-{resource['id']}", "state": "queued", "resource": resource,
            "adapter_intent": {"key": key, "action": "start"},
            "expected": {"uuid": resource["id"], "definition": resource["revision"], "state": "off"}})
    value = {"id": "1" * 32, "actor": "owner", "key": "adapter-test-key-0001", "package_digest": "2" * 64,
        "instance_id": "instance", "action": "start", "preview_id": "3" * 32, "controller": "4" * 32,
        "created_at": 1, "updated_at": 2, "targets": targets}
    value["digest"] = hashlib.sha256(dumps(model.intent(value))).hexdigest()
    return value


@pytest.fixture
def records():
    store = SimpleNamespace(db=sqlite3.connect(":memory:"), lock=threading.RLock())
    yield model.Records(store)
    store.db.close()


@pytest.mark.parametrize("count", [1, 64])
def test_profiles_are_immutable_and_retained_until_explicit_removal(records, count):
    for index in range(count):
        value = profile(index)
        records.save_profile(value)
        assert model.retained(records.store, endpoint_id=value["endpoint_id"])
        with pytest.raises(Failure, match="new profile"):
            records.save_profile({**value, "endpoint_revision": 2})
        changed = {**value, "enabled": True, "revision": 2}
        records.save_profile(changed)
        assert records.profile(value["id"]) == changed
    assert len(records.profiles()) == count
    for index in range(count):
        records.remove_profile(profile(index)["id"])
    assert not model.retained(records.store)


@pytest.mark.parametrize("count", [1, 64])
def test_durable_complete_batch_and_terminal_cleanup_retention(records, count):
    records.save_profile(profile())
    value = operation(count)
    records.insert(value)
    assert records.get(value["id"]) == value
    assert records.existing("owner", value["key"]) == value
    with pytest.raises(Failure, match="operation receipts"):
        records.remove_profile(profile()["id"])
    for target in value["targets"]:
        target["state"] = "failed"
        target["adapter_receipt"] = {"state": "failed", "token": {"task": target["resource"]["key"]},
                                     "completed": True, "result": "failure"}
    records.save(value)
    profiles = list(records.store.db.execute("SELECT * FROM module_adapter_profiles"))
    operations = list(records.store.db.execute("SELECT * FROM module_adapter_operations"))
    model.validate_records(profiles, operations, {profile()["endpoint_id"]}, {profile()["digest"]})
    assert model.retained(records.store, digest=profile()["digest"])
    value["cleanup"] = []
    records.save(value)
    operations = list(records.store.db.execute("SELECT * FROM module_adapter_operations"))
    with pytest.raises(ValueError, match="active or unknown"):
        model.validate_records(profiles, operations, {profile()["endpoint_id"]}, {profile()["digest"]})
    records.remove(value["id"])
    records.remove_profile(profile()["id"])
    assert not model.retained(records.store, endpoint_id=profile()["endpoint_id"])


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("changed", ["birth", "intent", "endpoint", "resource", "proof"])
def test_private_frozen_intent_and_completion_proof_reject_substitution(count, changed):
    value = operation(count)
    target = value["targets"][-1]
    if changed == "birth":
        target["resource"]["birth"] = "d" * 64
    elif changed == "intent":
        target["adapter_intent"]["action"] = "shutdown"
    elif changed == "endpoint":
        target["profile"]["endpoint_id"] = "d" * 32
    elif changed == "resource":
        target["vm_id"] = f"vm-{'d' * 32}-{target['resource']['id']}"
    else:
        target["state"] = "observed"
        target["adapter_receipt"] = {"state": "accepted", "token": {"task": "active"},
                                     "completed": False, "result": "unknown"}
    with pytest.raises((Failure, ValueError)):
        model.operation(value)


@pytest.mark.parametrize("count", [1, 64])
def test_history_capacity_reserves_completion_before_any_dispatch(records, monkeypatch, count):
    value = operation(count)
    maximum = model.reservation(value)
    monkeypatch.setattr(model, "MAX_HISTORY_BYTES", maximum - 1)
    with pytest.raises(Failure, match="completed provider receipts"):
        records.insert(value)
    assert records.all() == []
    monkeypatch.setattr(model, "MAX_HISTORY_BYTES", maximum)
    records.insert(value)
    for target in value["targets"]:
        target["state"] = "accepted"
        target["adapter_receipt"] = {"state": "accepted", "token": {"task": "x" * 4000},
                                     "completed": False, "result": "unknown"}
    records.save(value)
    assert len(dumps(value)) < maximum
    assert records.get(value["id"])["targets"][-1]["adapter_receipt"]["token"]["task"] == "x" * 4000


def test_unknown_schema_or_task_cannot_hide_retention(records):
    value = operation()
    target = value["targets"][0]
    target["state"] = "resolved"
    target["adapter_receipt"] = {"state": "accepted", "token": {"task": "pending"},
                                 "completed": False, "result": "unknown"}
    with pytest.raises(ValueError, match="active provider task"):
        model.operation(value)
    records.store.db.execute("DROP TABLE module_adapter_operations")
    with pytest.raises(ValueError, match="incomplete"):
        model.retained(records.store, endpoint_id=profile()["endpoint_id"])
