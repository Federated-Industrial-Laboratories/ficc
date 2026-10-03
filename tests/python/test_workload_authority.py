# SPDX-License-Identifier: Apache-2.0
"""Keep background delegation valid across logout and refuse changed project grants."""

import secrets

import pytest
from policy_fixtures import activate, install_pack
from project_module_fixtures import checked
from test_identity_projects import member
from workload_fixtures import contributor, submitted

from ficc.errors import Failure
from ficc.workloads.authority import Authority


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_logout_preserves_job_delegation_and_membership_change_revokes_it(policy_console, count):
    client, service, material = policy_console
    subjects = [member(service, f"Job member {index}", scopes=["jobs:execute", "contributors:read"])
                for index in range(max(2, count))]
    for user, project, _actor, _headers in subjects:
        checked(client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}",
                           json={"roles": ["operator"], "revision": 0}))
    activate(client, install_pack(client, material))
    authority = Authority(service)
    jobs = []
    for index, (_user, project, actor, _headers) in enumerate(subjects):
        node = contributor(service, project["id"], index)
        job = submitted(service, actor, node, index)
        authority.check(job, node["id"], enforcement=True)
        service.auth.revoke(actor.id)
        with pytest.raises(Failure, match="Sign in"):
            service.auth.current(actor.id)
        with pytest.raises(Failure, match="Sign in"):
            service.auth.current(job.delegation.id)
        authority.check(job, node["id"], enforcement=True)
        jobs.append((job, node))
    last = count - 1
    user, project, _actor, _headers = subjects[last]
    service.auth.identities.membership(project["id"], user["id"], [], 1)
    with pytest.raises(Failure):
        authority.check(jobs[last][0], jobs[last][1]["id"], enforcement=True)
    service.auth.identities.membership(project["id"], user["id"], ["jobs:execute", "contributors:read"], 2)
    with pytest.raises(Failure, match="changed after submission"):
        authority.check(jobs[last][0], jobs[last][1]["id"], enforcement=True)
    control = 0 if count > 1 else 1
    authority.check(jobs[control][0], jobs[control][1]["id"], enforcement=True)
    checked(client.put(f"/api/v1/projects/{project['id']}/policy-roles/{user['id']}",
                       json={"roles": ["observer"], "revision": 1}))
    authority.check(jobs[control][0], jobs[control][1]["id"], enforcement=True)
    with pytest.raises(Failure, match="changed after submission"):
        authority.check(jobs[last][0], jobs[last][1]["id"], enforcement=True)
    with pytest.raises(Failure, match="no longer permits"):
        authority.check(jobs[control][0], secrets.token_hex(16), enforcement=True)
