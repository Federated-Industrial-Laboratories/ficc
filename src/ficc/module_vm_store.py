# SPDX-License-Identifier: Apache-2.0
"""Keep bounded VM profiles and durable lifecycle operation records."""

import time

from ficc_node import vm_spec as spec

from .errors import Failure

TABLES = {"module_vm_profiles": ("node_id", "value"),
          "module_vm_operations": ("id", "actor", "key", "digest", "value")}


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS module_vm_profiles (node_id TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS module_vm_operations (id TEXT PRIMARY KEY, actor TEXT NOT NULL, "
               "key TEXT NOT NULL, digest TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(actor,key))")


def node_identity(node):
    return spec.digest({key: node[key] for key in ("id", "profile", "host", "account", "port", "key_type", "key")})


def profile(value):
    spec.fields(value, {"id", "node_id", "connection", "identity", "revision", "enabled"})
    spec.identity(value["id"])
    spec.text(value["node_id"], 128)
    spec.fingerprint(value["identity"])
    spec.integer(value["revision"], 1, 9007199254740991)
    if value["connection"] not in spec.CONNECTIONS or type(value["enabled"]) is not bool:
        raise ValueError("Invalid VM profile.")
    return value


def operation(value):
    spec.fields(value, {"id", "actor", "key", "digest", "package_digest", "instance_id", "action", "preview_id",
                        "controller", "created_at", "updated_at", "targets"}, {"cleanup"})
    for key in ("id", "controller", "preview_id"):
        spec.identity(value[key])
    for key in ("digest", "package_digest"):
        spec.fingerprint(value[key])
    for key in ("actor", "instance_id"):
        spec.text(value[key], 128)
    key = spec.text(value["key"], 128)
    if len(key) < 16 or not key.isascii() or value["action"] not in {"start", "shutdown"}:
        raise ValueError("Invalid VM operation identity.")
    for key in ("created_at", "updated_at"):
        if type(value[key]) not in (int, float) or not 0 <= value[key] < 1e12:
            raise ValueError("Invalid VM operation timestamp.")
    targets = value["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 64:
        raise ValueError("Invalid VM operation batch.")
    ids = []
    bindings: dict[str, dict] = {}
    for target in targets:
        spec.fields(target, {"node_id", "profile", "vm_id", "expected", "state"},
                    {"error", "observed_state", "observed_at"})
        profile(target["profile"])
        if target["node_id"] != target["profile"]["node_id"]:
            raise ValueError("Invalid VM target node.")
        if bindings.setdefault(target["node_id"], target["profile"]) != target["profile"]:
            raise ValueError("Conflicting VM profiles in one system batch.")
        pid, domain_id = spec.resource(target["vm_id"])
        spec.fields(target["expected"], {"uuid", "definition", "state"})
        spec.fingerprint(target["expected"]["definition"])
        if pid != target["profile"]["id"] or domain_id != target["expected"]["uuid"]:
            raise ValueError("Invalid VM target identity.")
        if target["expected"]["state"] not in spec.STATES.values():
            raise ValueError("Invalid VM expected state.")
        if target["state"] not in {"queued", "dispatching", "accepted", "refused", "unknown", "observed", "resolved"}:
            raise ValueError("Invalid VM operation state.")
        if "error" in target:
            spec.fields(target["error"], {"code", "message"})
            spec.text(target["error"]["code"], 96)
            spec.text(target["error"]["message"], 256)
        if "observed_state" in target and target["observed_state"] not in spec.STATES.values():
            raise ValueError("Invalid VM observed state.")
        if "observed_at" in target and (type(target["observed_at"]) not in (int, float)
                                       or not 0 <= target["observed_at"] < 1e12):
            raise ValueError("Invalid VM observation time.")
        ids.append(target["vm_id"])
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate VM operation targets.")
    frozen = [{key: target[key] for key in ("node_id", "profile", "vm_id", "expected")} | {"state": "queued"}
              for target in targets]
    if value["digest"] != spec.digest({"preview_id": value["preview_id"], "action": value["action"], "targets": frozen}):
        raise ValueError("The VM operation intent digest does not match.")
    if "cleanup" in value:
        done = value["cleanup"]
        profiles = {target["profile"]["id"] for target in targets}
        if (not isinstance(done, list) or len(done) > len(profiles) or any(not isinstance(item, str) for item in done)
                or len(set(done)) != len(done) or set(done) - profiles
                or any(target["state"] not in spec.TERMINAL for target in targets)):
            raise ValueError("Invalid VM receipt cleanup state.")
    return value


def validate_records(profiles, operations, node_ids):
    """Validate decoded backup rows; restored profiles must subsequently be disabled."""
    if len(profiles) > 64 or len(operations) > 1024:
        raise ValueError("VM record capacity exceeded.")
    profile_ids, profile_nodes, operation_ids, operation_keys = set(), set(), set(), set()
    for row in profiles:
        if len(row) != 2:
            raise ValueError("Invalid VM profile row.")
        value = profile(spec.decode(row[1].encode()))
        if row[0] != value["node_id"] or row[0] not in node_ids:
            raise ValueError("Invalid VM profile row identity.")
        if value["id"] in profile_ids or row[0] in profile_nodes:
            raise ValueError("Duplicate VM profile identity.")
        profile_ids.add(value["id"])
        profile_nodes.add(row[0])
    for row in operations:
        if len(row) != 5:
            raise ValueError("Invalid VM operation row.")
        value = operation(spec.decode(row[4].encode()))
        if tuple(row[:4]) != tuple(value[key] for key in ("id", "actor", "key", "digest")):
            raise ValueError("Invalid VM operation row identity.")
        if row[0] in operation_ids or (row[1], row[2]) in operation_keys:
            raise ValueError("Duplicate VM operation identity.")
        operation_ids.add(row[0])
        operation_keys.add((row[1], row[2]))
        if any(item["node_id"] not in node_ids for item in value["targets"]):
            raise ValueError("Missing VM operation node.")
        if "cleanup" in value or any(item["state"] not in spec.TERMINAL for item in value["targets"]):
            raise ValueError("An unfinished or unknown VM operation cannot be backed up or restored.")


class Records:
    def __init__(self, store):
        self.store = store
        with store.lock, store.db:
            initialize(store.db)

    def profiles(self):
        with self.store.lock:
            return [profile(spec.decode(row[0].encode())) for row in self.store.db.execute("SELECT value FROM module_vm_profiles")]

    def profile(self, node_id):
        found = next((item for item in self.profiles() if item["node_id"] == node_id), None)
        if found is None:
            raise Failure("vm_profile_missing", "Configure a libvirt connection for this system.", 409)
        return found

    def save_profile(self, value):
        profile(value)
        with self.store.lock, self.store.db:
            count = self.store.db.execute("SELECT count(*) FROM module_vm_profiles").fetchone()[0]
            exists = self.store.db.execute("SELECT 1 FROM module_vm_profiles WHERE node_id=?", (value["node_id"],)).fetchone()
            if count >= 64 and not exists:
                raise Failure("vm_capacity", "The VM profile limit is full.", 409)
            self.store.db.execute("INSERT INTO module_vm_profiles VALUES (?,?) ON CONFLICT(node_id) DO UPDATE SET value=excluded.value",
                                  (value["node_id"], spec.encode(value).decode()))

    def all(self):
        with self.store.lock:
            return [operation(spec.decode(row[0].encode())) for row in self.store.db.execute("SELECT value FROM module_vm_operations ORDER BY rowid DESC")]

    def get(self, operation_id):
        spec.identity(operation_id)
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_vm_operations WHERE id=?", (operation_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The VM operation was not found.", 404)
        return operation(spec.decode(row[0].encode()))

    def existing(self, actor, key):
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_vm_operations WHERE actor=? AND key=?", (actor, key)).fetchone()
        return operation(spec.decode(row[0].encode())) if row else None

    def insert(self, value):
        operation(value)
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM module_vm_operations").fetchone()[0] >= 1024:
                raise Failure("vm_capacity", "The retained VM operation limit is full.", 409)
            self.store.db.execute("INSERT INTO module_vm_operations VALUES (?,?,?,?,?)", (
                *[value[key] for key in ("id", "actor", "key", "digest")], spec.encode(value).decode()))

    def save(self, value):
        value["updated_at"] = time.time()
        operation(value)
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE module_vm_operations SET value=? WHERE id=?", (spec.encode(value).decode(), value["id"]))

    def retained(self, node_id):
        return any(item["node_id"] == node_id for item in self.profiles()) or any(
            target["node_id"] == node_id for value in self.all() for target in value["targets"])

    def remove(self, operation_id):
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM module_vm_operations WHERE id=?", (operation_id,))

    def remove_profile(self, node_id):
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM module_vm_profiles WHERE node_id=?", (node_id,))
