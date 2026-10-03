# SPDX-License-Identifier: Apache-2.0
"""Keep bounded container profiles and immutable lifecycle intent records."""

import time

from ficc_node import container_spec as spec

from .errors import Failure
from .module_vm_store import node_identity as node_identity

TABLES = {"module_container_profiles": ("id", "node_id", "value"),
          "module_container_operations": ("id", "actor", "key", "digest", "value")}


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS module_container_profiles (id TEXT PRIMARY KEY,node_id TEXT NOT NULL,value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS module_container_operations (id TEXT PRIMARY KEY,actor TEXT NOT NULL,key TEXT NOT NULL,"
               "digest TEXT NOT NULL,value TEXT NOT NULL,UNIQUE(actor,key))")


def profile(value):
    spec.fields(value, {"id", "node_id", "identity", "provider", "connection", "context", "namespace", "binding", "version", "account_uid", "revision", "enabled"})
    spec.identity(value["id"])
    spec.text(value["node_id"], 128)
    spec.fingerprint(value["identity"])
    spec.fingerprint(value["binding"])
    spec.text(value["version"], 128)
    spec.integer(value["account_uid"], 0, 2**32 - 1)
    spec.integer(value["revision"], 1, 2**53 - 1)
    if value["provider"] not in spec.PROVIDERS or type(value["enabled"]) is not bool:
        raise ValueError("Invalid container profile.")
    spec.config(value)
    return value


def intent(value):
    return {"preview_id": value["preview_id"], "action": value["action"], "replicas": value["replicas"],
            "targets": [{key: target[key] for key in ("node_id", "profile", "resource_id", "expected")} | {"state": "queued"}
                        for target in value["targets"]]}


def operation(value):
    spec.fields(value, {"id", "actor", "key", "digest", "package_digest", "instance_id", "action", "replicas", "preview_id",
                        "controller", "created_at", "updated_at", "targets"}, {"cleanup"})
    for key in ("id", "preview_id", "controller"):
        spec.identity(value[key])
    for key in ("actor", "instance_id"):
        spec.text(value[key], 128)
    for key in ("digest", "package_digest"):
        spec.fingerprint(value[key])
    key = spec.text(value["key"], 128)
    if len(key) < 16 or not key.isascii() or not key.isprintable() or value["action"] not in spec.ACTIONS:
        raise ValueError("Invalid container operation identity.")
    if value["action"] == "scale":
        spec.integer(value["replicas"], 0, 64)
    elif value["replicas"] is not None:
        raise ValueError("Only scale has a replica count.")
    for key in ("created_at", "updated_at"):
        if type(value[key]) not in {int, float} or not 0 <= value[key] < 1e12:
            raise ValueError("Invalid container operation timestamp.")
    if value["updated_at"] < value["created_at"]:
        raise ValueError("Invalid container operation clock order.")
    targets = value["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 64:
        raise ValueError("Invalid container operation batch.")
    ids = []
    for target in targets:
        spec.fields(target, {"node_id", "profile", "resource_id", "expected", "state"}, {"error", "observed", "observed_at"})
        profile(target["profile"])
        spec.expected(target["expected"])
        if target["node_id"] != target["profile"]["node_id"] or target["resource_id"] != spec.resource(target["profile"]["id"], target["expected"]["resource"]):
            raise ValueError("Invalid container target binding.")
        if target["state"] not in spec.TERMINAL | {"queued", "dispatching", "accepted", "unknown"}:
            raise ValueError("Invalid container operation state.")
        if "error" in target:
            spec.fields(target["error"], {"code", "message"})
            spec.text(target["error"]["code"], 96)
            spec.text(target["error"]["message"], 256)
        if "observed" in target:
            spec.fields(target["observed"], {"state", "replicas", "ready"})
            spec.text(target["observed"]["state"], 64)
            for key in ("replicas", "ready"):
                if target["observed"][key] is not None:
                    spec.integer(target["observed"][key], 0, 1000000)
        if "observed_at" in target and (type(target["observed_at"]) not in {int, float} or not 0 <= target["observed_at"] < 1e12):
            raise ValueError("Invalid container observation time.")
        ids.append(target["resource_id"])
    if len(ids) != len(set(ids)) or value["digest"] != spec.digest(intent(value)):
        raise ValueError("The frozen container intent does not match.")
    if "cleanup" in value:
        done = value["cleanup"]
        profiles = {item["profile"]["id"] for item in targets}
        if (not isinstance(done, list) or len(done) > len(profiles) or any(not isinstance(item, str) for item in done)
                or len(set(done)) != len(done) or set(done) - profiles or any(item["state"] not in spec.TERMINAL for item in targets)):
            raise ValueError("Invalid container receipt cleanup state.")
    return value


def validate_records(profiles, operations, node_ids, *, quiescent=True):
    if len(profiles) > 64 or len(operations) > 1024:
        raise ValueError("Container record capacity exceeded.")
    ids, keys = set(), set()
    for row in profiles:
        if len(row) != 3:
            raise ValueError("Invalid container profile row.")
        value = profile(spec.decode(row[2].encode()))
        if tuple(row[:2]) != (value["id"], value["node_id"]) or row[1] not in node_ids or row[0] in ids:
            raise ValueError("Invalid container profile identity.")
        ids.add(row[0])
    ids = set()
    for row in operations:
        if len(row) != 5:
            raise ValueError("Invalid container operation row.")
        value = operation(spec.decode(row[4].encode()))
        if tuple(row[:4]) != tuple(value[key] for key in ("id", "actor", "key", "digest")) or row[0] in ids or (row[1], row[2]) in keys:
            raise ValueError("Invalid container operation identity.")
        ids.add(row[0])
        keys.add((row[1], row[2]))
        if quiescent and ("cleanup" in value or any(item["state"] not in spec.TERMINAL for item in value["targets"])):
            raise ValueError("Resolve active or unknown container operations before backup or restore.")


def retained(store, *, node_id=None, profile_id=None, digest=None, instance_id=None):
    for value in Records(store).all():
        if digest is not None and value["package_digest"] != digest or instance_id is not None and value["instance_id"] != instance_id:
            continue
        if any((node_id is None or item["node_id"] == node_id) and (profile_id is None or item["profile"]["id"] == profile_id)
               and ("cleanup" in value or item["state"] not in spec.TERMINAL) for item in value["targets"]):
            return True
    return False


class Records:
    def __init__(self, store):
        self.store = store

    def profiles(self):
        with self.store.lock:
            return [profile(spec.decode(row[0].encode())) for row in self.store.db.execute("SELECT value FROM module_container_profiles ORDER BY id")]

    def profile(self, identity):
        spec.identity(identity)
        result = next((item for item in self.profiles() if item["id"] == identity), None)
        if result is None:
            raise Failure("container_profile_missing", "The container profile was not found.", 404)
        return result

    def save_profile(self, value):
        profile(value)
        with self.store.lock, self.store.db:
            exists = self.store.db.execute("SELECT 1 FROM module_container_profiles WHERE id=:p0", (value["id"],)).fetchone()
            if not exists and self.store.db.execute("SELECT count(*) FROM module_container_profiles").fetchone()[0] >= 64:
                raise Failure("container_capacity", "The container profile limit is full.", 409)
            self.store.db.execute("INSERT INTO module_container_profiles VALUES (:p0,:p1,:p2) ON CONFLICT(id) DO UPDATE SET node_id=excluded.node_id,value=excluded.value",
                                  (value["id"], value["node_id"], spec.encode(value).decode()))

    def all(self):
        with self.store.lock:
            return [operation(spec.decode(row[0].encode())) for row in self.store.db.execute("SELECT value FROM module_container_operations ORDER BY rowid DESC")]

    def get(self, identity):
        spec.identity(identity)
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_container_operations WHERE id=:p0", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The container operation was not found.", 404)
        return operation(spec.decode(row[0].encode()))

    def existing(self, actor, key):
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_container_operations WHERE actor=:p0 AND key=:p1", (actor, key)).fetchone()
        return operation(spec.decode(row[0].encode())) if row else None

    def insert(self, value):
        operation(value)
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT count(*) FROM module_container_operations").fetchone()[0] >= 1024:
                raise Failure("container_capacity", "The retained container operation limit is full.", 409)
            self.store.db.execute("INSERT INTO module_container_operations VALUES (:p0,:p1,:p2,:p3,:p4)", (*[value[key] for key in ("id", "actor", "key", "digest")], spec.encode(value).decode()))

    def save(self, value):
        value["updated_at"] = time.time()
        operation(value)
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE module_container_operations SET value=:p0 WHERE id=:p1", (spec.encode(value).decode(), value["id"]))

    def remove(self, identity):
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM module_container_operations WHERE id=:p0", (identity,))

    def remove_profile(self, identity):
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM module_container_profiles WHERE id=:p0", (identity,))
