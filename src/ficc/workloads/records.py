# SPDX-License-Identifier: Apache-2.0
"""Commit project jobs, exclusive reservations, and observed results atomically."""

import json
import secrets
import time

from ..errors import Failure
from ..execution.spec import AttemptResult, Plan, Renewal, digest, encoded
from ..policy_store import PolicyStore
from .schema import TERMINAL, Attempt, Delegation, Record, Submission


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS workload_jobs (id TEXT PRIMARY KEY,subject_id TEXT NOT NULL,"
               "project_id TEXT NOT NULL,key TEXT NOT NULL,digest TEXT NOT NULL,value TEXT NOT NULL,"
               "UNIQUE(subject_id,project_id,key))")
    db.execute("CREATE TABLE IF NOT EXISTS workload_attempts (id TEXT PRIMARY KEY,job_id TEXT NOT NULL,"
               "node_id TEXT NOT NULL,value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS workload_nodes (node_id TEXT PRIMARY KEY,value TEXT NOT NULL)")


class Records:
    def __init__(self, store):
        self.store = store

    def get(self, identity) -> Record:
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM workload_jobs WHERE id=:p0", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The workload was not found.", 404)
        return Record.model_validate_json(row[0])

    def attempt(self, identity) -> Attempt:
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM workload_attempts WHERE id=:p0", (identity,)).fetchone()
        if row is None:
            raise Failure("not_found", "The workload attempt was not found.", 404)
        return Attempt.model_validate_json(row[0])

    def jobs(self, project_id=None):
        sql = "SELECT value FROM workload_jobs"
        with self.store.lock:
            rows = self.store.db.execute(sql + (" WHERE project_id=:p0" if project_id else "") + " ORDER BY id",
                                         (project_id,) if project_id else ()).fetchall()
        return [Record.model_validate_json(row[0]) for row in rows]

    def attempts(self, node_id=None):
        sql = "SELECT value FROM workload_attempts"
        with self.store.lock:
            rows = self.store.db.execute(sql + (" WHERE node_id=:p0" if node_id else "") + " ORDER BY id",
                                         (node_id,) if node_id else ()).fetchall()
        return [Attempt.model_validate_json(row[0]) for row in rows]

    def save_job(self, value):
        value.updated_at = max(value.updated_at, time.time())
        value.revision += 1
        Record.model_validate(value.model_dump())
        self.store.db.execute("UPDATE workload_jobs SET value=:p0 WHERE id=:p1", (value.model_dump_json(), value.id))

    def save_attempt(self, value):
        value.updated_at = max(value.updated_at, time.time())
        Attempt.model_validate(value.model_dump())
        self.store.db.execute("UPDATE workload_attempts SET value=:p0 WHERE id=:p1", (value.model_dump_json(), value.id))

    def audit(self, action, job, attempt, outcome):
        self.store.audit(action, attempt.id, outcome, job.actor,
                         subject_id=job.subject_id, project_id=job.project_id)

    def submit(self, request: Submission, key: str, delegation: Delegation):
        with self.store.lock, self.store.db:
            binding = digest(request.model_dump())
            row = self.store.db.execute("SELECT value FROM workload_jobs WHERE subject_id=:p0 AND project_id=:p1 AND key=:p2",
                (delegation.subject_id, delegation.project_id, key)).fetchone()
            if row:
                value = Record.model_validate_json(row[0])
                if value.digest != binding:
                    raise Failure("idempotency_conflict", "This request key already identifies another workload.", 409)
                return value
            if self.store.db.execute("SELECT count(*) FROM workload_jobs").fetchone()[0] >= 2048:
                raise Failure("capacity", "Retained workload capacity is full. Remove completed records first.", 409)
            now = time.time()
            value = Record(id=secrets.token_hex(16), subject_id=delegation.subject_id, project_id=delegation.project_id,
                actor=delegation.credential_id, key=key, digest=binding, request=request, delegation=delegation,
                state="queued", reason=None, current_attempt=None, generation=0, cancelled=False,
                created_at=now, updated_at=now, revision=1)
            self.store.db.execute("INSERT INTO workload_jobs VALUES (:p0,:p1,:p2,:p3,:p4,:p5)",
                (value.id, value.subject_id, value.project_id, key, binding, value.model_dump_json()))
            return value

    def reserve(self, plan: Plan, lease: Renewal, installation_id: str, capacity, *, ledger_id=None, admission_version=0):
        with self.store.lock, self.store.db:
            job = self.get(plan.job_id)
            if (job.cancelled or job.state != "queued" or job.generation + 1 != plan.generation
                    or job.subject_id != plan.subject_id or job.project_id != plan.project_id
                    or plan.node_id not in job.request.node_ids or job.request.job != plan.job
                    or PolicyStore(self.store).state()["revision"] != plan.policy_revision):
                raise Failure("workload_changed", "The queued workload or its authority changed.", 409)
            if lease.sequence != 1 or lease.expires_at <= time.time():
                raise Failure("lease_expired", "The first workload lease is invalid or expired.", 409)
            held = [item for item in self.attempts(plan.node_id) if item.state != "released"]
            limits = plan.job.limits
            if not limits.fits(capacity):
                raise Failure("capacity", "The workload exceeds the offered node capacity.", 409)
            for key in ("cpu_millis", "memory_bytes", "swap_bytes", "processes", "storage_bytes", "storage_inodes"):
                if sum(getattr(item.plan.job.limits, key) for item in held) + getattr(limits, key) > getattr(capacity, key):
                    raise Failure("capacity", "The node capacity is reserved by another attempt.", 409)
            if any(set(limits.gpu_devices) & set(item.plan.job.limits.gpu_devices) for item in held):
                raise Failure("capacity", "A selected GPU is reserved by another attempt.", 409)
            if self.store.db.execute("SELECT count(*) FROM workload_attempts").fetchone()[0] >= 8192:
                raise Failure("capacity", "Retained attempt capacity is full. Remove completed records first.", 409)
            now = time.time()
            attempt = Attempt(id=plan.attempt_id, job_id=job.id, node_id=plan.node_id, installation_id=installation_id,
                              ledger_id=ledger_id, admission_version=admission_version,
                              plan=plan, lease=lease, observed=None, outcome=None, state="preparing", created_at=now, updated_at=now)
            self.store.db.execute("INSERT INTO workload_attempts VALUES (:p0,:p1,:p2,:p3)",
                                  (attempt.id, job.id, attempt.node_id, attempt.model_dump_json()))
            job.current_attempt, job.generation = attempt.id, plan.generation
            job.state, job.reason = "preparing", None
            self.save_job(job)
            self.audit("workload.admit", job, attempt, "preparing")
            return attempt

    def observation(self, result: AttemptResult, node_id: str, installation_id: str):
        with self.store.lock, self.store.db:
            attempt = self.attempt(result.attempt_id)
            if attempt.state == "abandoned":
                raise Failure("attempt_abandoned", "A retired contributor attempt cannot resume or change its recorded outcome.", 409)
            if ((attempt.node_id, attempt.installation_id) != (node_id, installation_id)
                    or result.generation != attempt.plan.generation or result.plan_digest != attempt.plan.digest()):
                raise Failure("attempt_changed", "The result does not bind this node and immutable attempt.", 409)
            if attempt.state == "released":
                if result != attempt.observed:
                    raise Failure("attempt_changed", "A released attempt cannot change its recorded result.", 409)
                return attempt
            if attempt.state in TERMINAL and result.state not in {attempt.state, "released", "unknown"}:
                raise Failure("attempt_changed", "The observed attempt cannot return to an active state.", 409)
            if (attempt.start_requested or attempt.state in {"starting", "running"}) and result.state == "prepared":
                raise Failure("attempt_changed", "The observed attempt cannot repeat preparation.", 409)
            job = self.get(attempt.job_id)
            if job.current_attempt != attempt.id:
                raise Failure("attempt_changed", "The result belongs to an earlier workload attempt.", 409)
            previous_state = attempt.state
            previous_cleanup = bool(attempt.observed and attempt.observed.cleanup_confirmed)
            if result.state in TERMINAL or result.state == "unknown" and result.cleanup_confirmed:
                if (attempt.outcome and attempt.outcome.model_dump(exclude={"cleanup_confirmed"})
                        != result.model_dump(exclude={"cleanup_confirmed"})):
                    raise Failure("attempt_changed", "The final workload outcome cannot change.", 409)
                attempt.outcome = result
            attempt.observed, attempt.state = result, result.state
            if result.state != "released":
                if (job.state, job.reason) != (result.state, result.reason):
                    job.state, job.reason = result.state, result.reason
                    self.save_job(job)
            elif job.state not in TERMINAL | {"unknown"} or attempt.outcome is None:
                raise Failure("attempt_changed", "Observe the final workload outcome before releasing its storage.", 409)
            self.save_attempt(attempt)
            if previous_state != attempt.state:
                self.audit("workload.observe", job, attempt, attempt.state)
            if not previous_cleanup and result.cleanup_confirmed:
                self.audit("workload.cleanup", job, attempt, "confirmed")
            return attempt

    def transition(self, identity, expected, state, reason=None):
        """Record dispatch intent before sending an operation with external effects."""
        allowed = {("prepared", "starting"), ("preparing", "unknown"), ("starting", "unknown"),
                   ("running", "unknown"), ("prepared", "unknown")}
        if (expected, state) not in allowed:
            raise ValueError("The controller attempt transition is invalid.")
        with self.store.lock, self.store.db:
            attempt = self.attempt(identity)
            job = self.get(attempt.job_id)
            if attempt.state != expected or job.current_attempt != identity or job.cancelled and state == "starting":
                raise Failure("attempt_changed", "The workload attempt changed before dispatch.", 409)
            attempt.state, job.state, job.reason = state, state, reason
            if state == "starting":
                attempt.start_requested = True
            self.save_attempt(attempt)
            self.save_job(job)
            self.audit("workload.start" if state == "starting" else "workload.observe", job, attempt, state)
            return attempt

    def renew(self, identity, expires_at):
        with self.store.lock, self.store.db:
            attempt = self.attempt(identity)
            job = self.get(attempt.job_id)
            if (attempt.state not in {"prepared", "starting", "running"} or job.cancelled
                    or job.current_attempt != identity or attempt.lease.expires_at <= time.time()
                    or not attempt.lease.expires_at < expires_at <= time.time() + 30):
                raise Failure("lease_expired", "The current workload lease cannot be renewed.", 409)
            attempt.lease = Renewal(attempt_id=identity, generation=attempt.plan.generation,
                                   plan_digest=attempt.plan.digest(), sequence=attempt.lease.sequence + 1, expires_at=expires_at)
            self.save_attempt(attempt)
            return attempt.lease

    def cancel(self, identity, revision):
        with self.store.lock, self.store.db:
            job = self.get(identity)
            if job.revision != revision:
                raise Failure("revision_conflict", "The workload changed. Reload it before cancelling.", 409)
            job.cancelled = True
            if job.state == "queued":
                job.state, job.reason = "cancelled", "cancelled_before_dispatch"
            self.save_job(job)
            return job

    def retry(self, identity, revision, delegation, *, acknowledge_unknown=False):
        with self.store.lock, self.store.db:
            job = self.get(identity)
            allowed = TERMINAL | ({"unknown"} if acknowledge_unknown else set())
            if (job.revision != revision or job.state not in allowed
                    or job.current_attempt and self.attempt(job.current_attempt).state != "released"):
                raise Failure("workload_unresolved", "Retry requires a completed workload with confirmed storage release.", 409)
            job.delegation = delegation
            job.state, job.reason, job.cancelled = "queued", None, False
            self.save_job(job)
            return job

    def pending(self, identity, reason):
        with self.store.lock, self.store.db:
            job = self.get(identity)
            if job.state == "queued" and job.reason != reason:
                job.reason = reason
                self.save_job(job)
            return job

    def abandon(self, identity, revision):
        with self.store.lock, self.store.db:
            job = self.get(identity)
            if job.revision != revision or job.state != "unknown" or job.current_attempt is None:
                raise Failure("workload_unresolved", "Reload an unknown attempt before abandoning the retired contributor record.", 409)
            attempt = self.attempt(job.current_attempt)
            if attempt.state in {"released", "abandoned"}:
                raise Failure("attempt_changed", "The workload attempt no longer holds an unresolved reservation.", 409)
            from ..contributor_store import Records as Contributors
            node = Contributors(self.store, None).get("contributors", attempt.node_id)
            if not node["disabled"]:
                raise Failure("contributor_active", "Revoke this contributor identity before abandoning its unresolved attempts.", 409)
            attempt.state = "abandoned"
            if attempt.outcome is None:
                before = attempt.observed
                attempt.outcome = AttemptResult(attempt_id=attempt.id, generation=attempt.plan.generation,
                    plan_digest=attempt.plan.digest(), state="unknown", reason="operator_abandoned", exit_code=None,
                    output_bytes=before.output_bytes if before else 0, error_bytes=before.error_bytes if before else 0,
                    cleanup_confirmed=False)
            job.cancelled, job.reason = True, "operator_abandoned"
            self.save_attempt(attempt)
            self.save_job(job)
            return job

    def remove(self, identity, revision):
        with self.store.lock, self.store.db:
            job = self.get(identity)
            attempts = [item for item in self.attempts() if item.job_id == job.id]
            retired = job.state == "unknown" and attempts and all(item.state in {"released", "abandoned"} for item in attempts)
            if (job.revision != revision or job.state not in TERMINAL and not retired
                    or any(item.state not in {"released", "abandoned"} for item in attempts)):
                raise Failure("workload_unresolved", "Remove only completed workloads with released attempts.", 409)
            self.store.db.execute("DELETE FROM workload_attempts WHERE job_id=:p0", (identity,))
            self.store.db.execute("DELETE FROM workload_jobs WHERE id=:p0", (identity,))


def validate_records(db, *, quiescent=True):
    projects = {row[0] for row in db.execute("SELECT id FROM projects")}
    subjects = {row[0] for row in db.execute("SELECT id FROM identities")}
    nodes = {row[0] for row in db.execute("SELECT id FROM contributors")}
    jobs: dict[str, Record] = {}
    attempts: dict[str, Attempt] = {}
    for identity, subject, project, key, binding, raw in db.execute("SELECT * FROM workload_jobs"):
        value = Record.model_validate_json(raw)
        if ((identity, subject, project, key, binding) != (value.id, value.subject_id, value.project_id, value.key, value.digest)
                or subject not in subjects or project not in projects or binding != digest(value.request.model_dump())):
            raise ValueError("A stored workload identity or submission is invalid.")
        if quiescent and value.state not in TERMINAL | {"unknown"}:
            raise ValueError("Resolve all active or unknown workloads before backup or restore.")
        jobs[identity] = value
    for identity, job, node, raw in db.execute("SELECT * FROM workload_attempts"):
        attempt = Attempt.model_validate_json(raw)
        if ((identity, job, node) != (attempt.id, attempt.job_id, attempt.node_id) or job not in jobs or node not in nodes
                or attempt.plan.subject_id != jobs[job].subject_id or attempt.plan.project_id != jobs[job].project_id
                or attempt.plan.job != jobs[job].request.job or node not in jobs[job].request.node_ids):
            raise ValueError("A stored workload attempt is not bound to its submission.")
        if attempt.state == "abandoned":
            row = db.execute("SELECT value FROM contributors WHERE id=:p0", (node,)).fetchone()
            if row is None or not json.loads(row[0])["disabled"]:
                raise ValueError("An abandoned attempt requires a revoked contributor identity.")
        if quiescent and attempt.state not in {"released", "abandoned"}:
            raise ValueError("Resolve active or unknown outcomes and release workload storage before backup or restore.")
        attempts[identity] = attempt
    for job in jobs.values():
        if quiescent and job.state == "unknown" and not (
                job.current_attempt in attempts and attempts[job.current_attempt].state == "abandoned"):
            raise ValueError("Resolve all active or unknown workloads before backup or restore.")
        if job.current_attempt is not None:
            current = attempts.get(job.current_attempt)
            if current is None or current.job_id != job.id or current.plan.generation != job.generation:
                raise ValueError("The latest workload generation is invalid.")
        generations = [item.plan.generation for item in attempts.values() if item.job_id == job.id]
        if len(generations) != len(set(generations)) or any(value > job.generation for value in generations):
            raise ValueError("A retained workload generation is duplicated or out of order.")
    from .node_records import validate_records as validate_nodes
    validate_nodes(db, nodes)


def suspend(db):
    db.execute("INSERT INTO settings VALUES ('workloads.suspended',:p0) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (encoded(True).decode(),))
    for identity, raw in db.execute("SELECT id,value FROM workload_jobs").fetchall():
        value = json.loads(raw)
        value["cancelled"] = True
        value["revision"] += 1
        db.execute("UPDATE workload_jobs SET value=:p0 WHERE id=:p1", (encoded(value).decode(), identity))
