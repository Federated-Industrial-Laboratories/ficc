# SPDX-License-Identifier: Apache-2.0
"""Keep retained attempt accounting project-scoped and exact above browser integers."""

from test_identity_projects import member
from workload_fixtures import INSTALLATION, contributor, placement, submitted

from ficc.execution.spec import AttemptResult


def test_usage_excludes_other_projects_and_preserves_exact_reported_bytes(console):
    client, service = console
    _user, project, principal, headers = member(service, "Accounted project")
    _user2, _project2, _principal2, outside = member(service, "Other project")
    node = contributor(service, project["id"])
    job = submitted(service, principal, node)
    plan, lease = placement(job, node["id"])
    service.workloads.records.reserve(plan, lease, INSTALLATION, plan.job.limits)
    observed = AttemptResult(attempt_id=plan.attempt_id, generation=plan.generation, plan_digest=plan.digest(),
        state="succeeded", reason=None, exit_code=0, output_bytes=2**53 + 1, error_bytes=0, cleanup_confirmed=True)
    service.workloads.records.observation(observed, node["id"], INSTALLATION)
    value = client.get("/api/v1/workloads", headers=headers).json()["usage"]
    assert value["attempts"] == value["unreleased_attempts"] == 1
    assert value["reported_stdout_bytes"] == str(2**53 + 1)
    assert value["states"] == {"succeeded": 1}
    assert value["reservations"]["memory_bytes"] == plan.job.limits.memory_bytes
    other = client.get("/api/v1/workloads", headers=outside).json()["usage"]
    assert other["attempts"] == 0 and other["reported_stdout_bytes"] == 0
