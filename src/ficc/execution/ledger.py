# SPDX-License-Identifier: Apache-2.0
"""Keep local offers, attempt fences, and exclusive reservations durable."""

import json
import os
import re
import secrets
import sqlite3
import stat
import threading
from pathlib import Path

from ..state_provider import AtomicConnection
from .clock import Reading, active, deadline
from .offer import Offer
from .spec import AttemptResult, Plan, encoded

TERMINAL = frozenset({"succeeded", "failed", "cancelled", "expired"})


class Conflict(ValueError):
    """Keep refused and uncertain local operations separate from successful work."""


class Ledger:
    def __init__(self, directory: Path, installation: str):
        self.lock = threading.RLock()
        self.path = directory / "execution.sqlite3"
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("The execution state directory must be private and owned by the service account.")
        if not self.path.exists() and not self.path.is_symlink():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("The execution database must be a private regular file.")
        self.db = sqlite3.connect(self.path, check_same_thread=False, factory=AtomicConnection)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            if self.db.execute("PRAGMA user_version").fetchone()[0] not in {0, 1}:
                raise ValueError("The local execution schema is not supported.")
            with self.db:
                self.db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, "
                                "generation INTEGER NOT NULL, plan_digest TEXT NOT NULL, state TEXT NOT NULL, "
                                "slot TEXT UNIQUE, value TEXT NOT NULL, UNIQUE(job_id,generation))")
                self.db.execute("CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, "
                                "attempt_id TEXT NOT NULL REFERENCES attempts(id))")
                previous = self.setting("installation_id")
                if previous is not None and previous != installation:
                    raise ValueError("The execution state belongs to another installation.")
                self.setting("installation_id", installation)
                identity = self.setting("ledger_id")
                if identity is None:
                    identity = self.setting("ledger_id", secrets.token_hex(16))
                if not isinstance(identity, str) or not re.fullmatch("[0-9a-f]{32}", identity):
                    raise ValueError("The durable execution ledger identity is invalid.")
                self.identity = identity
                self.db.execute("PRAGMA user_version=1")
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def setting(self, key, value=None):
        with self.lock:
            if value is None:
                row = self.db.execute("SELECT value FROM settings WHERE key=:p0", (key,)).fetchone()
                return json.loads(row[0]) if row else None
            with self.db:
                self.db.execute("INSERT INTO settings VALUES (:p0,:p1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                                (key, encoded(value).decode()))
                return value

    def offer(self) -> Offer | None:
        value = self.setting("offer")
        return Offer.model_validate(value) if value is not None else None

    def save_offer(self, value: Offer, expected: int):
        with self.lock, self.db:
            before = self.offer()
            if (before.revision if before else 0) != expected or value.revision != expected + 1:
                raise Conflict("The local offer changed. Reload it before saving.")
            if before is not None and before.mode != value.mode:
                raise Conflict("Only the machine administrator can change the installed contribution mode.")
            self.setting("offer", value.model_dump())

    def get(self, identity: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT value FROM attempts WHERE id=:p0", (identity,)).fetchone()
            return json.loads(row[0]) if row else None

    def all(self) -> list[dict]:
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute("SELECT value FROM attempts ORDER BY id")]

    def page(self, after=None, limit=64):
        with self.lock:
            rows = self.db.execute("SELECT value FROM attempts WHERE id>:p0 ORDER BY id LIMIT :p1",
                                   (after or "", limit + 1)).fetchall()
            return [json.loads(row[0]) for row in rows[:limit]], len(rows) > limit

    def retained(self):
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute("SELECT value FROM attempts WHERE slot IS NOT NULL ORDER BY id")]

    def annotate(self, fence, **fields):
        with self.lock, self.db:
            value = self.fenced(fence.attempt_id, fence.generation, fence.plan_digest)
            if set(fields) - {"prepared_runtime", "engine_released", "payload_released", "pending_stop", "input_progress"}:
                raise ValueError("The local executor annotation is not supported.")
            value.update(fields)
            self.save(value)
            return value

    def admit(self, admission, slot, binding, now, maximum_seconds):
        with self.lock, self.db:
            before = self.get(admission.plan.attempt_id)
            value = self.reserve(admission.plan, slot, binding, now.wall)
            if before is None:
                value = self.renew(admission.lease, now, maximum_seconds)
            return value, before is None

    def save(self, value):
        self.db.execute("UPDATE attempts SET state=:p0,slot=:p1,value=:p2 WHERE id=:p3",
                        (value["state"], value["slot"], encoded(value).decode(), value["plan"]["attempt_id"]))

    def reject(self, plan: Plan, now: float, *, observation=None):
        """Fence an unadmitted plan without rewriting any existing outcome."""
        with self.lock, self.db:
            before = self.get(plan.attempt_id)
            if before is not None:
                return self.fenced(plan.attempt_id, plan.generation, plan.digest())
            same_job = [item for item in self.all() if item["plan"]["job_id"] == plan.job_id]
            if any(item["state"] != "released" or item["plan"]["generation"] >= plan.generation for item in same_job):
                raise Conflict("A previous job generation remains reserved or the new generation is stale.")
            state = "unknown" if observation is not None else "failed"
            reason = "legacy_absence_acknowledged" if observation is not None else "admission_rejected"
            value = {"plan": plan.model_dump(), "plan_digest": plan.digest(), "slot": None,
                     "binding": None, "state": state, "cleanup_confirmed": True,
                     "lease_sequence": 0, "lease_expires_at": 0.0, "created_at": now,
                     "reason": reason, "exit_code": None, "output_bytes": 0, "error_bytes": 0,
                     "admission_rejection": {"ledger_id": self.identity, "observation": observation}}
            self.db.execute("INSERT INTO attempts VALUES (:p0,:p1,:p2,:p3,:p4,:p5,:p6)",
                            (plan.attempt_id, plan.job_id, plan.generation, plan.digest(), state, None, encoded(value).decode()))
            return value

    def reserve(self, plan: Plan, slot: str, binding: dict, now: float):
        """Reserve only after independent configuration and OS checks have passed."""
        with self.lock, self.db:
            identity = plan.attempt_id
            before = self.get(identity)
            if before is not None:
                if before["plan_digest"] != plan.digest():
                    raise Conflict("The attempt identity belongs to another immutable plan.")
                return before
            offer = self.offer()
            if offer is None or offer.revision != plan.offer_revision:
                raise Conflict("The local offer is absent or changed.")
            reason = offer.refusal(plan.project_id, plan.job, now)
            if reason:
                raise Conflict(reason)
            attempts = self.all()
            same_job = [item for item in attempts if item["plan"]["job_id"] == plan.job_id]
            if any(item["state"] != "released" or item["plan"]["generation"] >= plan.generation for item in same_job):
                raise Conflict("A previous job generation remains reserved or the new generation is stale.")
            held = [item for item in attempts if item["slot"] is not None]
            if any(item["slot"] == slot for item in held):
                raise Conflict("The storage slot is reserved or awaits confirmed cleanup.")
            running = [item for item in held if not item.get("cleanup_confirmed", False)]
            for name in ("cpu_millis", "memory_bytes", "swap_bytes", "processes"):
                amount = getattr(plan.job.limits, name) + sum(item["plan"]["job"]["limits"][name] for item in running)
                if amount > getattr(offer.limits, name):
                    raise Conflict("The local offer has insufficient available resources.")
            for name in ("storage_bytes", "storage_inodes"):
                amount = getattr(plan.job.limits, name) + sum(item["plan"]["job"]["limits"][name] for item in held)
                if amount > getattr(offer.limits, name):
                    raise Conflict("The local offer has insufficient unreserved storage.")
            devices = {row[0] for row in self.db.execute("SELECT id FROM devices")}
            if devices.intersection(plan.job.limits.gpu_devices):
                raise Conflict("A selected GPU is reserved or awaits confirmed cleanup.")
            value = {"plan": plan.model_dump(), "plan_digest": plan.digest(), "slot": slot,
                     "binding": binding, "state": "prepared", "cleanup_confirmed": False,
                     "lease_sequence": 0, "lease_expires_at": 0.0, "created_at": now,
                     "reason": None, "exit_code": None, "output_bytes": 0, "error_bytes": 0}
            self.db.execute("INSERT INTO attempts VALUES (:p0,:p1,:p2,:p3,:p4,:p5,:p6)",
                            (identity, plan.job_id, plan.generation, plan.digest(), "prepared", slot, encoded(value).decode()))
            for device in plan.job.limits.gpu_devices:
                self.db.execute("INSERT INTO devices VALUES (:p0,:p1)", (device, identity))
            return value

    def fenced(self, identity, generation, plan_digest):
        value = self.get(identity)
        if value is None or value["plan"]["generation"] != generation or value["plan_digest"] != plan_digest:
            raise Conflict("The operation does not name the current immutable attempt.")
        return value

    def start_requested(self, fence, now: Reading):
        with self.lock, self.db:
            value = self.fenced(fence.attempt_id, fence.generation, fence.plan_digest)
            if value["state"] != "prepared":
                return value, False
            if not active(value, now):
                raise Conflict("A current local execution lease is required before start.")
            plan = Plan.model_validate(value["plan"])
            offer = self.offer()
            if offer is None or offer.revision != plan.offer_revision:
                raise Conflict("The local offer changed before start.")
            if reason := offer.refusal(plan.project_id, plan.job, now.wall):
                raise Conflict(reason)
            value["state"] = "starting"
            self.save(value)
            return value, True

    def started(self, fence, binding):
        with self.lock, self.db:
            value = self.fenced(fence.attempt_id, fence.generation, fence.plan_digest)
            if value["state"] != "starting":
                raise Conflict("The attempt is not awaiting its first observed start.")
            value.update(state="running", runtime_binding=binding)
            self.save(value)

    def renew(self, request, now: Reading, maximum_seconds: float):
        with self.lock, self.db:
            value = self.fenced(request.attempt_id, request.generation, request.plan_digest)
            if value["state"] not in {"prepared", "starting", "running"}:
                raise Conflict("A completed or uncertain attempt cannot receive a new lease.")
            if value["lease_sequence"] and not active(value, now):
                raise Conflict("The previous execution lease has expired.")
            plan = Plan.model_validate(value["plan"])
            offer = self.offer()
            if offer is None or (reason := offer.refusal(plan.project_id, plan.job, now.wall, continuing=True)):
                raise Conflict(reason if offer else "The local offer is absent.")
            running = [item for item in self.all() if item["slot"] is not None and not item["cleanup_confirmed"]]
            for name in ("cpu_millis", "memory_bytes", "swap_bytes", "processes"):
                if sum(item["plan"]["job"]["limits"][name] for item in running) > getattr(offer.limits, name):
                    raise Conflict("The current attempts exceed the reduced local offer.")
            if request.sequence <= value["lease_sequence"]:
                if request.sequence == value["lease_sequence"] and request.expires_at == value["lease_expires_at"]:
                    return value
                raise Conflict("The execution lease sequence is stale or changed.")
            try:
                timing = deadline(request.expires_at, now, maximum_seconds)
            except ValueError as exc:
                raise Conflict(str(exc)) from None
            value.update(lease_sequence=request.sequence, lease_expires_at=request.expires_at, **timing)
            self.save(value)
            return value

    def finish(self, result: AttemptResult):
        with self.lock, self.db:
            value = self.fenced(result.attempt_id, result.generation, result.plan_digest)
            if value["state"] == "released":
                raise Conflict("The attempt has already been released.")
            if result.state not in TERMINAL | {"unknown"}:
                raise Conflict("Record an observed terminal or uncertain outcome.")
            if result.state in TERMINAL and not result.cleanup_confirmed:
                raise Conflict("A terminal result requires confirmed workload cleanup.")
            if value["state"] in TERMINAL and value["state"] != result.state:
                raise Conflict("The observed terminal outcome cannot be replaced.")
            value.update(result.model_dump(exclude={"attempt_id", "generation", "plan_digest"}))
            self.save(value)
            if result.cleanup_confirmed:
                self.db.execute("DELETE FROM devices WHERE attempt_id=:p0", (result.attempt_id,))

    def release(self, fence):
        """Commit release after storage cleanup and OS identity checks, never before."""
        with self.lock, self.db:
            value = self.fenced(fence.attempt_id, fence.generation, fence.plan_digest)
            if value["state"] == "released":
                return value
            if value["state"] not in TERMINAL | {"unknown"} or not value["cleanup_confirmed"]:
                raise Conflict("The attempt outcome or cleanup remains unconfirmed.")
            value.update(outcome=value["state"], state="released", slot=None)
            self.save(value)
            self.db.execute("DELETE FROM devices WHERE attempt_id=:p0", (fence.attempt_id,))
            return value

    def recover_storage(self, fence, before, binding, observed_at):
        """Record an administrator-confirmed empty remount without replaying its work."""
        with self.lock, self.db:
            value = self.fenced(fence.attempt_id, fence.generation, fence.plan_digest)
            if value["state"] == "released" or value["binding"] != before:
                raise Conflict("The retained storage binding changed before recovery.")
            records = value.get("storage_recovery", [])
            if len(records) >= 64:
                raise Conflict("This attempt has reached its storage recovery record limit.")
            records.append({"before": before, "after": binding, "observed_at": observed_at})
            value.update(binding=binding, cleanup_confirmed=True, storage_recovery=records)
            if value["state"] not in TERMINAL:
                value.update(state="unknown", reason="storage_recovered_outcome_unknown", exit_code=None)
            self.save(value)
            self.db.execute("DELETE FROM devices WHERE attempt_id=:p0", (fence.attempt_id,))
            return value
