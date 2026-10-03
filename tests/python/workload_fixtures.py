# SPDX-License-Identifier: Apache-2.0
"""Build synthetic contributor metadata and immutable controller workload plans."""

import json
import secrets
import time

from test_execution_ledger import plan as sample_plan

from ficc.execution.spec import AttemptResult, Plan, Renewal
from ficc.workloads.authority import Authority
from ficc.workloads.records import Records
from ficc.workloads.schema import Submission

INSTALLATION = "a" * 32


def contributor(service, project, index=0, mode="managed"):
    value = {"id": f"{index + 500:032x}", "project_id": project, "name": f"Synthetic contributor {index}",
             "mode": mode, "disabled": False, "revision": 1, "created_at": time.time()}
    with service.store.lock, service.store.db:
        service.store.db.execute("INSERT INTO contributors VALUES (:p0,:p1,:p2)",
                                (value["id"], project, json.dumps(value)))
    return value


def submitted(service, actor, node, index=0):
    request = Submission(job=sample_plan(index).job, node_ids=[node["id"]])
    delegation = Authority(service).capture(actor, request)
    value = Records(service.store).submit(request, secrets.token_hex(16), delegation)
    return value


def placement(job, node_id, generation=None):
    plan = Plan(version=1, deployment_id="b" * 32, node_id=node_id,
        project_id=job.project_id, subject_id=job.subject_id, job_id=job.id,
        attempt_id=secrets.token_hex(16), generation=generation or job.generation + 1,
        offer_revision=1, policy_revision=job.delegation.policy_revision, job=job.request.job)
    lease = Renewal(attempt_id=plan.attempt_id, generation=plan.generation,
                    plan_digest=plan.digest(), sequence=1, expires_at=time.time() + 30)
    return plan, lease


def result(plan, state="succeeded", cleanup=True):
    return AttemptResult(attempt_id=plan.attempt_id, generation=plan.generation,
        plan_digest=plan.digest(), state=state, reason=None, exit_code=0 if state == "succeeded" else None,
        output_bytes=71, error_bytes=0, cleanup_confirmed=cleanup)
