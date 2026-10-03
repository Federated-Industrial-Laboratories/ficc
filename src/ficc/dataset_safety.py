# SPDX-License-Identifier: Apache-2.0
"""Apply current owner safety decisions without rewriting immutable manifests."""

import hashlib
import time

from .dataset_store import encoded
from .errors import Failure
from .inspection_schema import Exemption, SafetyChange
from .inspection_sdk import InspectionError, load
from .inspection_store import InspectionStore, index


class DatasetSafety:
    def __init__(self, service):
        self.service, self.store = service, InspectionStore(service.store)

    def config(self):
        from .inspection_schema import InspectionConfig
        return InspectionConfig.model_validate(self.service.store.get_setting("inspection_config", {})).model_dump()

    def register(self, value, inputs=()):
        index(self.service.store.db, value, inputs)
        policy = self.store.policy(value["id"])
        policy["inspection_required"] = self.config()["required_new"]
        self.store.policy_save(policy)

    def successful(self, policy, config):
        approved = self.service.store.get_setting("inspection_approval", None)
        try:
            if not config["provider"]:
                return False
            module, installed = load(config["provider"])
            if installed != approved:
                return False
            from .inspection_runtime import approved_assets
            approved_assets(self.service, module, config["configuration"])
        except (InspectionError, Failure, ImportError, OSError, ValueError):
            return False
        if not policy["latest_run"]:
            return False
        run = self.store.run(policy["latest_run"])
        return (run["state"] == "completed" and run["outcome"] == "no_detection"
                and run["config_digest"] == hashlib.sha256(encoded(config)).hexdigest()
                and time.time() - run.get("finished_at", 0) <= config["max_age_seconds"])

    def effective(self, value):
        config = self.config()
        basis = hashlib.sha256(encoded(config))
        sensitive = required = quarantined = inherited_block = False
        ancestors = 0
        for policy in self.store.ancestors(value):
            basis.update(encoded({key: policy[key] for key in ("id", "revision", "latest_run")}))
            if policy["latest_run"]:
                run = self.store.run(policy["latest_run"])
                basis.update(encoded({key: run.get(key) for key in ("state", "outcome", "finished_at")}))
            sensitive |= policy["sensitive"]
            required |= policy["inspection_required"]
            quarantined |= policy["quarantined"]
            inherited_block |= policy["inspection_required"] and not self.successful(policy, config)
            ancestors += policy["id"] != value["id"]
        own = self.store.policy(value["id"])
        scan = self.store.run(own["latest_run"]) if own["latest_run"] else None
        missing = required and (not self.successful(own, config) or inherited_block)
        reason = "quarantined" if quarantined else "inspection_required" if missing else None
        exemption = own["exemption"]
        exempt = bool(exemption and exemption["basis_digest"] == basis.hexdigest()
                      and (exemption["expires_at"] is None or exemption["expires_at"] > time.time()))
        return {"sensitive": sensitive, "inspection_required": required, "quarantined": quarantined,
                "blocked": bool(reason and not exempt), "reason": reason, "exempt": exempt,
                "exemption": exemption, "basis_digest": basis.hexdigest(), "inherited_count": ancestors,
                "controls": own, "inspection": scan}

    def require(self, value):
        current = self.effective(value)
        if current["blocked"]:
            raise Failure("dataset_" + current["reason"], "This dataset is blocked by its current inspection or quarantine policy.", 403)
        return current

    def owner(self, actor):
        current = self.service.datasets.artifacts.current(actor)
        current.require("files:write")
        if not current.local_owner or current.node_ids is not None or current.root_ids is not None:
            raise Failure("denied", "An unrestricted local owner is required to change dataset safety policy.", 403)
        return current

    def update(self, identity, body, actor, *, exemption=False):
        self.service.live()
        body = (Exemption if exemption else SafetyChange).model_validate(body).model_dump()
        current = self.owner(actor)
        dataset = self.service.datasets.get(identity, actor)
        with self.service.store.lock, self.service.store.db:
            value = self.store.policy(identity)
            if value["revision"] != body["revision"]:
                raise Failure("safety_changed", "Refresh the current dataset safety controls before changing them.", 409)
            value["revision"] += 1
            value["exemption"] = None
            if not exemption:
                value.update({key: body[key] for key in ("sensitive", "inspection_required", "quarantined")})
            value["last_change"] = {"reason": body["reason"], "subject_id": current.subject_id, "at": time.time()}
            self.store.policy_save(value)
            if exemption and body["enabled"]:
                if body["expires_at"] is not None and body["expires_at"] <= time.time():
                    raise Failure("exemption_expired", "Choose a future exemption expiry.")
                value["exemption"] = {"reason": body["reason"], "expires_at": body["expires_at"], "subject_id": current.subject_id,
                                      "at": time.time(), "basis_digest": self.effective(dataset)["basis_digest"]}
                self.store.policy_save(value)
            self.service.store.audit("dataset.exemption" if exemption else "dataset.safety", identity,
                encoded({"revision": value["revision"], "reason": body["reason"]}).decode(), current.id,
                subject_id=current.subject_id, project_id=current.project_id)
        return self.effective(dataset)
