# SPDX-License-Identifier: Apache-2.0
"""Keep background job authority separate from expiring browser credentials."""

import json
import secrets

from .. import policy_provider
from ..auth import Principal
from ..errors import Failure
from ..identity_store import LOCAL_OWNER
from .schema import Delegation


class Authority:
    def __init__(self, service):
        self.service = service

    def stamp(self, subject, project):
        identities = self.service.auth.identities
        scopes = identities.access(subject, project)
        user, space = identities.user(subject), identities.project(project)
        row = self.service.store.db.execute(
            "SELECT revision FROM project_memberships WHERE subject_id=:p0 AND project_id=:p1", (subject, project)).fetchone()
        roles = self.service.store.db.execute(
            "SELECT revision FROM policy_bindings WHERE subject_id=:p0 AND project_id=:p1", (subject, project)).fetchone()
        policy = self.service.policies.records
        state = policy.state()
        publisher_revision = 0
        if state["active"]:
            publisher = self.service.store.db.execute(
                "SELECT p.revision,p.enabled FROM policy_publishers p JOIN policy_packages b "
                "ON b.publisher=p.id WHERE b.digest=:p0", (state["active"],)).fetchone()
            if publisher is None or not publisher[1]:
                raise Failure("policy_publisher_untrusted", "The active policy publisher is not trusted.", 403)
            publisher_revision = publisher[0]
        return scopes, {"subject_revision": user["revision"], "project_revision": space["revision"],
                        "membership_revision": row[0] if row else 0,
                        "policy_revision": state["revision"], "role_revision": roles[0] if roles else 0,
                        "policy_digest": state["active"], "publisher_revision": publisher_revision}

    def capture(self, actor, request):
        with self.service.store.lock:
            current = self.service.auth.current(actor.id)
            current.require("jobs:execute")
            current.require("contributors:read")
            if current.node_ids is not None or current.root_ids is not None:
                raise Failure("denied", "Contributor submission requires an unrestricted credential within its project.", 403)
            _scopes, stamp = self.stamp(current.subject_id, current.project_id)
            for identity in request.node_ids:
                self.node(current.project_id, identity)
            return Delegation(id=secrets.token_hex(16), subject_id=current.subject_id,
                project_id=current.project_id, credential_id=current.id, scopes=sorted(current.scopes), **stamp)

    def node(self, project, identity):
        value = self.service.contributors.records.get("contributors", identity)
        if value["project_id"] != project:
            raise Failure("not_found", "The contributor was not found in this project.", 404)
        if value["disabled"]:
            raise Failure("contributor_disabled", "The contributor is disabled.", 403)
        return value

    def current(self, delegation):
        scopes, stamp = self.stamp(delegation.subject_id, delegation.project_id)
        # Unrelated project bindings do not revoke this subject's durable delegation.
        if any(getattr(delegation, key) != value for key, value in stamp.items() if key != "policy_revision"):
            raise Failure("delegation_changed", "Project, identity, or policy authority changed after submission.", 403)
        return Principal(delegation.id, "Workload delegation", sorted(scopes & set(delegation.scopes)),
                         None, "", "workload", 0, None, delegation.subject_id, delegation.project_id)

    def check(self, job, node_id, *, enforcement):
        """Evaluate current policy without turning a job delegation into an API credential."""
        with self.service.store.lock:
            if job.cancelled or node_id not in job.request.node_ids:
                raise Failure("workload_cancelled", "The workload delegation no longer permits execution.", 403)
            current = self.current(job.delegation)
            current.require_host("jobs:execute")
            current.require_host("contributors:read")
            safety = self.service.workloads.inputs.check(job) if job.request.dataset is not None else None
            node = self.node(job.project_id, node_id)
            sensitive = job.request.job.sensitive or bool(safety and safety["sensitive"])
            if sensitive and node["mode"] != "managed":
                raise Failure("sensitive_workload", "Sensitive workloads require an approved managed contributor.", 403)
            policies = self.service.policies
            state = policies.records.state()
            if not state["required"]:
                raise Failure("policy_required", "Activate an approved policy package before contributor execution.", 409)
            authority = {**policies.authority(current), "contributor_id": node_id, "contributor_mode": node["mode"],
                         "contributor_revision": node["revision"], "contributor_enforcement": enforcement,
                         "job_id": job.id, "delegation_id": job.delegation.id,
                         "initiating_credential_id": job.actor, "local_owner": current.subject_id == LOCAL_OWNER}
            request = policy_provider.request("jobs:execute", authority,
                {"workload": {**job.request.job.model_dump(), "sensitive": sensitive}, "candidate_node_id": node_id})
            result = policies.decisions([request], state)[0]
            fresh = self.current(job.delegation)
            if (fresh.scopes != current.scopes or policies.records.state() != state
                    or self.node(job.project_id, node_id) != node
                    or policies.records.roles(job.project_id, job.subject_id) != authority["roles"]):
                raise Failure("policy_changed", "Authority changed during workload evaluation.", 409)
            if not result["allow"]:
                raise Failure("policy_denied", "The active policy denies this workload: " + result["reason"] + ".", 403)
            return state["revision"]


def retained_for_node(store, identity):
    with store.lock:
        row = store.db.execute("SELECT id FROM workload_attempts WHERE node_id=:p0 LIMIT 1", (identity,)).fetchone()
        if row is not None:
            return True
        for raw, in store.db.execute("SELECT value FROM workload_jobs"):
            value = json.loads(raw)
            if identity in value["request"]["node_ids"] and value["state"] not in {"succeeded", "failed", "cancelled", "expired"}:
                return True
        return False
