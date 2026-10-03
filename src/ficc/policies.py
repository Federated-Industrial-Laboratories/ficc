# SPDX-License-Identifier: Apache-2.0
"""Intersect current host authority with supervised, revision-bound policy decisions."""

import json
import os
import tempfile
import threading
from pathlib import Path

from . import policy_provider
from .auth import Principal
from .errors import Failure
from .policy_store import PolicyStore
from .settings import SCOPES


class Prepared:
    def __init__(self, state, payload):
        self.directory = tempfile.TemporaryDirectory(prefix="ficc-policy-")
        self.runner = None
        try:
            root = Path(self.directory.name)
            source, run = root / "source", root / "run"
            source.mkdir(mode=0o700)
            run.mkdir(mode=0o700)
            for name, data in payload.items():
                path = source / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(data)
            self.runner = policy_provider.prepare(state, source, run)
            probe = policy_provider.request("policy:probe", {"local_owner": False, "roles": [], "scopes": [],
                                                            "contributor_enforcement": False})
            policy_provider.evaluate(self.runner, [probe], 0)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.runner is not None:
            self.runner.close()
        self.runner = None
        self.directory.cleanup()


class Policies:
    def __init__(self, service):
        self.service = service
        self.records = PolicyStore(service.store)
        self.prepared = None
        self.digest = None
        self.publisher = None
        self.error = None
        self.retired = []
        self.preview_slots = threading.BoundedSemaphore(2)
        state = self.records.state()
        self.required = state["required"]
        if state["active"]:
            try:
                _, payload, publisher = self.records.package(state["active"])
                self.prepared = Prepared(service.settings.state_dir, payload)
                self.digest, self.publisher = state["active"], publisher
            except (ValueError, OSError, Failure):
                self.error = "The required policy is unavailable. Restore its trusted evaluator or activate a verified package."

    def close(self):
        if self.prepared is not None:
            self.prepared.close()
            self.prepared = None
        for prepared in list(self.retired):
            prepared.close()
            self.retired.remove(prepared)

    def status(self):
        state = self.records.state()
        try:
            configured = policy_provider.configuration(self.service.settings.state_dir) is not None
        except (ValueError, OSError):
            configured = False
        return {**state, "ready": bool(self.prepared and self.digest == state["active"] and not self.error),
                "error": self.error, "provider_configured": configured,
                "contributor_enforcement": False}

    def owner(self, actor):
        value = self.service.auth.current(actor)
        value.require_host("policies:manage")
        if not value.local_owner or value.node_ids is not None or value.root_ids is not None:
            raise Failure("denied", "Local owner policy administration is required.", 403)
        return value

    def event(self, action, target, actor, outcome="success"):
        self.service.store.audit("policy." + action, target, outcome, actor.id,
                                 subject_id=actor.subject_id, project_id=actor.project_id)

    def cleanup(self, prepared, actor, target, *, required=True):
        self.retired.append(prepared)
        try:
            prepared.close()
            self.retired.remove(prepared)
        except Exception:
            message = ("Policy cleanup failed. The saved change remains committed. Restart the evaluator to restore access."
                       if required else "Policy preview cleanup failed. Restart the controller before another preview.")
            if required:
                self.error = message
            self.event("cleanup", target, actor, "failed")
            raise Failure("policy_unavailable", message, 503) from None

    def trust(self, identity, key, enabled, expected, actor):
        self.service.live()
        with self.service.store.lock:
            owner = self.owner(actor)
            with self.service.store.db:
                result = self.records.trust(identity, key, enabled, expected)
                self.event("publisher", identity, owner)
            if self.publisher and self.publisher["id"] == identity and self.prepared is not None:
                previous, self.prepared = self.prepared, None
                self.cleanup(previous, owner, identity)
        return result

    def bind(self, project, subject, roles, expected, actor):
        self.service.live()
        with self.service.store.lock, self.service.store.db:
            owner = self.owner(actor)
            result = self.records.bind(project, subject, roles, expected)
            self.event("roles", project + "/" + subject, owner)
            return result

    def activate(self, digest, expected, actor):
        self.service.live()
        self.owner(actor)
        for pending in list(self.retired):
            try:
                pending.close()
            except Exception:
                raise Failure("policy_unavailable", "Complete pending evaluator cleanup before activation.", 503) from None
            self.retired.remove(pending)
        manifest, payload, publisher = self.records.package(digest)
        candidate = Prepared(self.service.settings.state_dir, payload)
        previous = None
        try:
            with self.service.store.lock:
                owner = self.owner(actor)
                if self.records.publisher(manifest["publisher"]) != publisher:
                    raise Failure("revision_conflict", "Publisher trust changed during policy preparation.", 409)
                with self.service.store.db:
                    state = self.records.activate(digest, expected)
                    self.event("activate", digest, owner)
                previous, self.prepared = self.prepared, candidate
                self.digest, self.publisher, self.error = digest, publisher, None
                self.required = True
        except BaseException:
            candidate.close()
            raise
        if previous is not None:
            self.cleanup(previous, owner, digest)
        return state

    def install(self, raw, actor):
        self.service.live()
        with self.service.store.lock, self.service.store.db:
            owner = self.owner(actor)
            result = self.records.install(raw)
            self.event("install", result["digest"], owner)
            return result

    def authority(self, principal, node_id=None, root_id=None):
        return {"subject_id": principal.subject_id, "project_id": principal.project_id,
                "credential_id": principal.id, "local_owner": principal.local_owner,
                "roles": self.records.roles(principal.project_id, principal.subject_id),
                "scopes": principal.scopes, "node_id": node_id, "root_id": root_id,
                "contributor_enforcement": False}

    def check(self, principal, action, node_id=None, root_id=None):
        # Only this controller can activate policy; activation makes enforcement permanent.
        if not self.required:
            return
        self.check_many(principal, [(action, node_id, root_id)])

    def check_many(self, principal, requirements):
        """Check one current authority snapshot without retaining decisions between calls."""
        selected = list(dict.fromkeys(requirements))
        if not selected:
            return
        with self.service.store.lock:
            current = self.service.auth.current(principal.id)
            for action, node_id, root_id in selected:
                current.require_host(action, node_id, root_id)
            if not self.required:
                return
            state = self.records.state()
            if not state["required"]:
                return
            authority = self.authority(current)
            requests = [policy_provider.request(action, {**authority, "node_id": node_id, "root_id": root_id})
                        for action, node_id, root_id in selected]
            results = []
            for offset in range(0, len(requests), 64):
                results.extend(self.decisions(requests[offset:offset + 64], state))
            fresh = self.service.auth.current(principal.id)
            for action, node_id, root_id in selected:
                fresh.require_host(action, node_id, root_id)
            if authority != self.authority(fresh) or state != self.records.state():
                raise Failure("policy_changed", "Access changed during policy evaluation. Retry the request.", 409)
            denied = next((result for result in results if not result["allow"]), None)
            if denied is not None:
                raise Failure("policy_denied", "The active policy denies this action: " + denied["reason"] + ".", 403)

    def decisions(self, requests, state, candidate=None):
        policy_provider.envelope(requests, state["revision"])
        try:
            prepared = candidate or self.prepared
            if prepared is None or prepared.runner is None:
                raise ValueError("No prepared evaluator")
            if candidate is None:
                if (self.error or self.publisher is None or self.digest != state["active"]
                        or self.publisher != self.records.publisher(self.publisher["id"])):
                    raise ValueError("The active publisher or package changed")
            return policy_provider.evaluate(prepared.runner, requests, state["revision"])
        except (ValueError, OSError, Failure, TypeError):
            if candidate is None:
                self.error = "The required policy is unavailable. Activate a verified package to restore access."
            raise Failure("policy_unavailable", "The required policy evaluator is unavailable. Access is denied.", 503) from None

    def preview(self, actor, requests, *, digest=None, subject=None, project=None):
        if not self.preview_slots.acquire(blocking=False):
            raise Failure("capacity", "Wait for a policy preview to finish.", 429)
        try:
            return self.preview_checked(actor, requests, digest=digest, subject=subject, project=project)
        finally:
            self.preview_slots.release()

    def preview_checked(self, actor, requests, *, digest=None, subject=None, project=None):
        principal = self.service.auth.current(actor)
        initiator = principal
        if not isinstance(requests, list) or not 1 <= len(requests) <= 64:
            raise ValueError("Select from one to 64 policy decisions.")
        if digest is not None or subject is not None or project is not None:
            self.owner(actor)
        selected_subject, selected_project = subject or principal.subject_id, project or principal.project_id
        candidate = None
        try:
            initial = self.records.state()
            selected_digest = digest or initial["active"]
            if digest is None and initial["required"] and not self.status()["ready"]:
                raise Failure("policy_unavailable", "The required policy is unavailable. Access is denied.", 503)
            if self.retired:
                raise Failure("policy_unavailable", "Restart the evaluator to complete pending policy cleanup.", 503)
            if selected_digest is not None:
                _, payload, _ = self.records.package(selected_digest)
                candidate = Prepared(self.service.settings.state_dir, payload)
            with self.service.store.lock:
                principal = self.service.auth.current(actor)
                if digest is not None or subject is not None or project is not None:
                    self.owner(actor)
                state = self.records.state()
                if state != initial:
                    raise Failure("policy_changed", "Policy state changed during preview preparation. Retry the request.", 409)
                if subject is not None or project is not None:
                    scopes = sorted(self.service.auth.identities.access(selected_subject, selected_project))
                    resources = self.service.auth.resources.get(selected_project)
                    principal = Principal("membership-preview", "Membership preview", scopes, None, "", "preview", 0,
                                          None, selected_subject, selected_project, resources["node_ids"], resources["root_ids"])
                asks, host = [], []
                for item in requests:
                    if not isinstance(item, dict) or set(item) - {"action", "node_id", "root_id", "labels"} or item.get("action") not in SCOPES:
                        raise ValueError("Select a supported policy action.")
                    node, root = item.get("node_id"), item.get("root_id")
                    if any(value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 128)
                           for value in (node, root)):
                        raise ValueError("Select valid policy resource identities.")
                    if node is not None:
                        self.service.store.endpoint_kind(node)
                    if root is not None:
                        registered = self.service.files.store.root(root)
                        if node != registered.get("node_id"):
                            raise ValueError("Select the registered folder's machine.")
                    labels = item.get("labels", {})
                    if not isinstance(labels, dict) or len(json.dumps(labels)) > 4096:
                        raise ValueError("Policy preview labels exceed their limit.")
                    try:
                        principal.require_host(item["action"], node, root)
                        allowed = True
                    except Failure:
                        allowed = False
                    host.append(allowed)
                    asks.append(policy_provider.request(item["action"], self.authority(principal, node, root), labels))
                decisions = (self.decisions(asks, state, candidate) if state["required"] or candidate else
                             [{"id": item["id"], "allow": True, "reason": "host_grants_only"} for item in asks])
                fresh = self.service.auth.current(actor)
                if digest is not None or subject is not None or project is not None:
                    self.owner(actor)
                if subject is not None or project is not None:
                    scopes = sorted(self.service.auth.identities.access(selected_subject, selected_project))
                    resources = self.service.auth.resources.get(selected_project)
                    if (scopes != principal.scopes or resources["node_ids"] != principal.project_nodes
                            or resources["root_ids"] != principal.project_roots):
                        raise Failure("policy_changed", "Membership changed during the preview.", 409)
                elif self.authority(fresh) != self.authority(principal):
                    raise Failure("policy_changed", "Access changed during the preview.", 409)
                if state != self.records.state():
                    raise Failure("policy_changed", "Policy state changed during the preview.", 409)
                return {"revision": state["revision"], "digest": digest or state["active"],
                        "membership_preview": subject is not None or project is not None,
                        "decisions": [{"action": asked["action"], "host_allowed": permitted,
                                       "policy_allowed": decision["allow"], "allowed": permitted and decision["allow"],
                                       "reason": decision["reason"] if permitted else "host_grant_denied"}
                                      for asked, permitted, decision in zip(asks, host, decisions, strict=True)]}
        finally:
            if candidate is not None:
                self.cleanup(candidate, initiator, selected_digest, required=False)
