# SPDX-License-Identifier: Apache-2.0
"""Retain Proxmox implementation pins and durable provider task outcomes."""

import copy
import time

from ficc_node import proxmox_spec as spec

from . import module_vm_store as common
from .errors import Failure

TABLES = {"module_proxmox_profiles": ("node_id", "value"),
          "module_proxmox_operations": ("id", "actor", "key", "digest", "value")}
TERMINAL = spec.TERMINAL


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS module_proxmox_profiles (node_id TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS module_proxmox_operations (id TEXT PRIMARY KEY, actor TEXT NOT NULL, "
               "key TEXT NOT NULL, digest TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(actor,key))")


def profile(value):
    spec.fields(value, {"id", "node_id", "connection", "identity", "revision", "enabled", "provider"})
    spec.provider(value["provider"])
    if value["connection"] != "local":
        raise ValueError("Only the fixed local Proxmox connection is supported.")
    common.profile({key: item for key, item in value.items() if key != "provider"} | {"connection": "system"})
    return value


def intent(value):
    return {"preview_id": value["preview_id"], "action": value["action"], "targets": [
        {key: target[key] for key in ("node_id", "profile", "vm_id", "expected")} | {"state": "queued"}
        for target in value["targets"]]}


def normalized(value):
    """Validate provider-specific fields, then reuse the shared record contract."""
    result = copy.deepcopy(value)
    bindings: dict[str, dict] = {}
    for target in result["targets"]:
        current = profile(target["profile"])
        if bindings.setdefault(target["node_id"], current) != current:
            raise ValueError("Conflicting Proxmox profiles in one system batch.")
        pid, domain_id = spec.resource(target["vm_id"])
        vmid = spec.vmid(domain_id)
        task = target.get("task")
        if "task" in target:
            target.pop("task")
            spec.task(task, node=current["provider"]["node"], expected_vmid=vmid, action=result["action"])
        if target["state"] in {"accepted", "observed"} and task is None:
            raise ValueError("An accepted Proxmox operation requires its exact task identity.")
        if target["state"] == "observed" and not spec.task_succeeded(task):
            raise ValueError("An observed Proxmox operation requires a successful stopped task.")
        if target["state"] == "resolved" and task is not None and task["state"] != "stopped":
            raise ValueError("An active provider task cannot be explicitly resolved.")
        if target["state"] == "failed":
            if task is None or task["state"] != "stopped" or spec.task_succeeded(task):
                raise ValueError("A failed Proxmox operation requires its exact stopped task result.")
            target["state"] = "refused"
        target["profile"] = {key: item for key, item in current.items() if key != "provider"} | {"connection": "system"}
        target["vm_id"] = f"libvirt-{pid}-{domain_id}"
    if value["digest"] != spec.digest(intent(value)):
        raise ValueError("The frozen Proxmox intent does not match.")
    result["digest"] = spec.digest(intent(result))
    common.operation(result)
    return result


def operation(value):
    normalized(value)
    return value


def validate_records(profiles, operations, node_ids):
    if len(profiles) > 64 or len(operations) > 1024:
        raise ValueError("Proxmox record capacity exceeded.")
    converted_profiles, converted_operations = [], []
    for row in profiles:
        if len(row) != 2:
            raise ValueError("Invalid Proxmox profile row.")
        value = profile(spec.decode(row[1].encode()))
        value = {key: item for key, item in value.items() if key != "provider"} | {"connection": "system"}
        converted_profiles.append((row[0], spec.encode(value).decode()))
    for row in operations:
        if len(row) != 5:
            raise ValueError("Invalid Proxmox operation row.")
        value = operation(spec.decode(row[4].encode()))
        if tuple(row[:4]) != tuple(value[key] for key in ("id", "actor", "key", "digest")):
            raise ValueError("Invalid Proxmox operation row identity.")
        value = normalized(value)
        converted_operations.append((*[value[key] for key in ("id", "actor", "key", "digest")], spec.encode(value).decode()))
    common.validate_records(converted_profiles, converted_operations, node_ids)


class Records(common.Records):
    def __init__(self, store):
        self.store = store

    def profiles(self):
        with self.store.lock:
            return [profile(spec.decode(row[0].encode())) for row in self.store.db.execute("SELECT value FROM module_proxmox_profiles")]

    def profile(self, node_id):
        found = next((item for item in self.profiles() if item["node_id"] == node_id), None)
        if found is None:
            raise Failure("proxmox_profile_missing", "Configure the local Proxmox connection for this system.", 409)
        return found

    def save_profile(self, value):
        profile(value)
        with self.store.lock, self.store.db:
            count = self.store.db.execute("SELECT count(*) FROM module_proxmox_profiles").fetchone()[0]
            exists = self.store.db.execute("SELECT 1 FROM module_proxmox_profiles WHERE node_id=:p0", (value["node_id"],)).fetchone()
            if count >= 64 and not exists:
                raise Failure("proxmox_capacity", "The Proxmox profile limit is full.", 409)
            self.store.db.execute("INSERT INTO module_proxmox_profiles VALUES (:p0,:p1) ON CONFLICT(node_id) DO UPDATE SET value=excluded.value",
                                  (value["node_id"], spec.encode(value).decode()))

    def all(self):
        with self.store.lock:
            return [operation(spec.decode(row[0].encode())) for row in self.store.db.execute("SELECT value FROM module_proxmox_operations ORDER BY rowid DESC")]

    def get(self, operation_id):
        spec.identity(operation_id)
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_proxmox_operations WHERE id=:p0", (operation_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The Proxmox operation was not found.", 404)
        return operation(spec.decode(row[0].encode()))

    def existing(self, actor, key):
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_proxmox_operations WHERE actor=:p0 AND key=:p1", (actor, key)).fetchone()
        return operation(spec.decode(row[0].encode())) if row else None

    def insert(self, value):
        operation(value)
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM module_proxmox_operations").fetchone()[0] >= 1024:
                raise Failure("proxmox_capacity", "The retained Proxmox operation limit is full.", 409)
            self.store.db.execute("INSERT INTO module_proxmox_operations VALUES (:p0,:p1,:p2,:p3,:p4)", (
                *[value[key] for key in ("id", "actor", "key", "digest")], spec.encode(value).decode()))

    def save(self, value):
        value["updated_at"] = time.time()
        operation(value)
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE module_proxmox_operations SET value=:p0 WHERE id=:p1", (spec.encode(value).decode(), value["id"]))

    def retained(self, node_id):
        return any(item["node_id"] == node_id for item in self.profiles()) or any(
            target["node_id"] == node_id for value in self.all() for target in value["targets"])

    def remove(self, operation_id):
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM module_proxmox_operations WHERE id=:p0", (operation_id,))

    def remove_profile(self, node_id):
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM module_proxmox_profiles WHERE node_id=:p0", (node_id,))
