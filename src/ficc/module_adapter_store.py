# SPDX-License-Identifier: Apache-2.0
"""Retain immutable provider bindings and bounded, unreplayed VM operation records."""

import copy
import hashlib
import time

from . import module_vm_store as common
from .errors import Failure
from .modules import adapter_protocol as spec
from .modules.adapter_manifest import CONSISTENCY
from .modules.adapter_vm_protocol import pending_task, receipt, resource_id
from .modules.validation import MAX_JSON, digest, dumps, fields, loads

TABLES = {"module_adapter_profiles": ("id", "endpoint_id", "digest", "value"),
          "module_adapter_operations": ("id", "actor", "key", "digest", "value")}
TERMINAL = frozenset({"observed", "refused", "resolved", "failed"})
MAX_HISTORY_BYTES = 16 * 1024 * 1024
IMMUTABLE = {"id", "digest", "endpoint_kind", "endpoint_id", "endpoint_revision",
             "machine_identity", "transport_binding_id", "consistency"}


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS module_adapter_profiles "
               "(id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL, digest TEXT NOT NULL, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS module_adapter_operations (id TEXT PRIMARY KEY, actor TEXT NOT NULL, "
               "key TEXT NOT NULL, digest TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(actor,key))")


def profile(value):
    fields(value, IMMUTABLE | {"revision", "enabled"}, {"provider"})
    for name in ("id", "endpoint_id", "transport_binding_id"):
        spec.identity(value[name])
    for name in ("digest", "machine_identity"):
        digest(value[name])
    for name in ("revision", "endpoint_revision"):
        spec.integer(value[name])
    if (value["endpoint_kind"] not in ("linux-ssh", "windows")
            or value["consistency"] not in tuple(CONSISTENCY) or type(value["enabled"]) is not bool):
        raise ValueError("Invalid adapter endpoint, consistency or enabled state.")
    if "provider" in value:
        fields(value["provider"], {"name", "version", "fingerprint"})
        spec.plain(value["provider"]["name"], 160)
        spec.plain(value["provider"]["version"], 160)
        digest(value["provider"]["fingerprint"])
    return value


def intent(value):
    keys = ("node_id", "profile", "vm_id", "expected", "resource", "adapter_intent")
    return {"preview_id": value["preview_id"], "action": value["action"],
            "targets": [{key: target[key] for key in keys} | {"state": "queued"} for target in value["targets"]]}


def operation(value):
    normalized = copy.deepcopy(value)
    for target in normalized["targets"]:
        current = profile(target["profile"])
        if target["node_id"] != current["endpoint_id"]:
            raise ValueError("The adapter operation endpoint does not match its profile.")
        resource = spec.resource(target.pop("resource"))
        if (resource["id"] != resource_id(resource["key"], resource["birth"])
                or target["vm_id"] != f"vm-{current['id']}-{resource['id']}"
                or target["expected"] != {"uuid": resource["id"], "definition": resource["revision"], "state": resource["state"]}):
            raise ValueError("The adapter operation resource identity does not match.")
        private_intent = spec.private(target.pop("adapter_intent"))
        if len(dumps(private_intent)) > 4096:
            raise ValueError("The private provider intent exceeds its limit.")
        proof = receipt(target.pop("adapter_receipt")) if "adapter_receipt" in target else None
        if target["state"] in {"accepted", "observed", "failed"} and proof is None:
            raise ValueError("The provider outcome requires its exact receipt.")
        if target["state"] in {"observed", "failed"}:
            assert proof is not None
            if not proof["completed"] or proof["result"] != ("success" if target["state"] == "observed" else "failure"):
                raise ValueError("The completed provider outcome lacks matching proof.")
        if target["state"] == "resolved" and pending_task(proof):
            raise ValueError("An active provider task retains its operation receipt.")
        if target["state"] == "failed":
            target["state"] = "refused"
        target["profile"] = {"id": current["id"], "node_id": current["endpoint_id"], "connection": "system",
            "identity": current["machine_identity"], "enabled": current["enabled"], "revision": current["revision"]}
        target["vm_id"] = f"libvirt-{current['id']}-{resource['id']}"
    if value["digest"] != hashlib.sha256(dumps(intent(value))).hexdigest():
        raise ValueError("The frozen adapter intent digest does not match.")
    targets = [{key: target[key] for key in ("node_id", "profile", "vm_id", "expected")} | {"state": "queued"}
               for target in normalized["targets"]]
    normalized["digest"] = hashlib.sha256(dumps({"preview_id": value["preview_id"],
        "action": value["action"], "targets": targets})).hexdigest()
    common.operation(normalized)
    return value


def retained(store, *, endpoint_id=None, digest=None, profile_id=None):
    """Keep all profile and history references, including disabled and terminal records."""
    def matches(value):
        return ((endpoint_id is None or value["endpoint_id"] == endpoint_id)
                and (digest is None or value["digest"] == digest)
                and (profile_id is None or value["id"] == profile_id))
    with store.lock:
        tables = store.table_names()
        if not tables.intersection(TABLES):
            return False
        if not set(TABLES) <= tables:
            raise ValueError("The adapter record schema is incomplete.")
        for row in store.db.execute("SELECT value FROM module_adapter_profiles"):
            if matches(profile(loads(row[0].encode()))):
                return True
        for row in store.db.execute("SELECT value FROM module_adapter_operations"):
            if any(matches(target["profile"]) for target in operation(loads(row[0].encode()))["targets"]):
                return True
    return False


def reservation(value):
    """Reserve completion bytes before dispatch, so a full history cannot lose a receipt."""
    return len(dumps(intent(value))) + 8192 * len(value["targets"]) + 4096


def validate_records(profiles, operations, endpoint_ids, package_digests):
    """Validate quiescent backups; restore must disable profiles and remove all grants."""
    if len(profiles) > 64 or len(operations) > 1024:
        raise ValueError("The adapter record capacity is invalid.")
    known, keys, identities, size = {}, set(), set(), 0
    for row in profiles:
        if len(row) != 4:
            raise ValueError("Invalid adapter profile row.")
        value = profile(loads(row[3].encode()))
        allowed_endpoints = endpoint_ids.get(value["endpoint_kind"], set()) if isinstance(endpoint_ids, dict) else endpoint_ids
        if (tuple(row[:3]) != tuple(value[key] for key in ("id", "endpoint_id", "digest"))
                or value["id"] in known or value["endpoint_id"] not in allowed_endpoints
                or value["digest"] not in package_digests):
            raise ValueError("Invalid adapter profile row identity.")
        known[value["id"]] = value
    for row in operations:
        if len(row) != 5:
            raise ValueError("Invalid adapter operation row.")
        value = operation(loads(row[4].encode()))
        if (tuple(row[:4]) != tuple(value[key] for key in ("id", "actor", "key", "digest"))
                or value["id"] in identities or (value["actor"], value["key"]) in keys):
            raise ValueError("Invalid adapter operation row identity.")
        identities.add(value["id"])
        keys.add((value["actor"], value["key"]))
        if "cleanup" in value or any(target["state"] not in TERMINAL for target in value["targets"]):
            raise ValueError("An active or unknown provider operation cannot be backed up or restored.")
        for target in value["targets"]:
            current = known.get(target["profile"]["id"])
            if current is None or any(current[key] != target["profile"][key] for key in IMMUTABLE):
                raise ValueError("The provider operation profile is missing or changed.")
        reserved = reservation(value)
        if reserved > MAX_JSON:
            raise ValueError("The provider operation exceeds its reserved byte limit.")
        size += reserved
    if size > MAX_HISTORY_BYTES:
        raise ValueError("The retained provider history exceeds its reserved byte limit.")


class Records(common.Records):
    def __init__(self, store):
        self.store = store

    def profiles(self):
        with self.store.lock:
            return [profile(loads(row[0].encode())) for row in self.store.db.execute("SELECT value FROM module_adapter_profiles")]

    def profile(self, profile_id):
        spec.identity(profile_id)
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_adapter_profiles WHERE id=:p0", (profile_id,)).fetchone()
        if row is None:
            raise Failure("adapter_profile_missing", "The provider adapter profile was not found.", 404)
        return profile(loads(row[0].encode()))

    def save_profile(self, value):
        profile(value)
        with self.store.lock, self.store.db:
            row = self.store.db.execute("SELECT value FROM module_adapter_profiles WHERE id=:p0", (value["id"],)).fetchone()
            if row:
                prior = profile(loads(row[0].encode()))
                if (any(prior[key] != value[key] for key in IMMUTABLE)
                        or "provider" in prior and prior["provider"] != value.get("provider")):
                    raise Failure("adapter_profile_changed", "A changed provider binding requires a new profile.", 409)
            elif self.store.db.execute("SELECT count(*) FROM module_adapter_profiles").fetchone()[0] >= 64:
                raise Failure("capacity", "The provider adapter profile limit is full.", 409)
            self.store.db.execute("INSERT INTO module_adapter_profiles VALUES (:p0,:p1,:p2,:p3) "
                "ON CONFLICT(id) DO UPDATE SET value=excluded.value", (value["id"], value["endpoint_id"],
                value["digest"], dumps(value).decode()))

    def all(self):
        with self.store.lock:
            return [operation(loads(row[0].encode())) for row in self.store.db.execute(
                "SELECT value FROM module_adapter_operations ORDER BY rowid DESC")]

    def get(self, operation_id):
        spec.identity(operation_id)
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_adapter_operations WHERE id=:p0", (operation_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The provider operation was not found.", 404)
        return operation(loads(row[0].encode()))

    def existing(self, actor, key):
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM module_adapter_operations WHERE actor=:p0 AND key=:p1",
                                         (actor, key)).fetchone()
        return operation(loads(row[0].encode())) if row else None

    def insert(self, value):
        operation(value)
        data = dumps(value).decode()
        with self.store.lock, self.store.db:
            prior = self.all()
            required = reservation(value)
            if len(prior) >= 1024 or required > MAX_JSON or sum(map(reservation, prior)) + required > MAX_HISTORY_BYTES:
                raise Failure("capacity", "Remove completed provider receipts before creating more operations.", 409)
            self.store.db.execute("INSERT INTO module_adapter_operations VALUES (:p0,:p1,:p2,:p3,:p4)",
                (*[value[key] for key in ("id", "actor", "key", "digest")], data))

    def save(self, value):
        value["updated_at"] = time.time()
        operation(value)
        data = dumps(value).decode()
        if len(data) > reservation(value):
            raise ValueError("The provider receipt exceeds its reserved record space.")
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE module_adapter_operations SET value=:p0 WHERE id=:p1", (data, value["id"]))

    def retained(self, node_id):
        return retained(self.store, endpoint_id=node_id)

    def remove(self, operation_id):
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM module_adapter_operations WHERE id=:p0", (operation_id,))

    def remove_profile(self, profile_id):
        with self.store.lock, self.store.db:
            if any(target["profile"]["id"] == profile_id for value in self.all() for target in value["targets"]):
                raise Failure("adapter_history", "Remove this profile's operation receipts before its profile.", 409)
            self.store.db.execute("DELETE FROM module_adapter_profiles WHERE id=:p0", (profile_id,))
