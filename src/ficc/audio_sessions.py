# SPDX-License-Identifier: Apache-2.0
"""Grant short playback leases to one authenticated surface per module instance."""

import json
import secrets
import time

from .errors import Failure
from .workspace_store import WorkspaceStore


class AudioSessions:
    def __init__(self, service):
        self.service = service
        self.leases: dict[str, dict] = {}

    def authorize(self, actor: str, instance_id: str) -> None:
        principal = self.service.auth.current(actor)
        principal.require("audio:playback")
        principal.require("workspaces:read")
        if principal.node_ids is not None or principal.root_ids is not None:
            raise Failure("denied", "Workspace audio requires an unrestricted workspace credential.", 403)
        for workspace in self.service.workspaces.all():
            for item in workspace["instances"]:
                if item["id"] == instance_id:
                    self.service.modules.require(item["digest"], "audio:playback", [workspace["id"]])
                    self.service.modules.require(item["digest"], "workspace:read", [workspace["id"]])
                    return
        raise Failure("not_found", "The audio module instance was not found.", 404)

    def prune(self) -> None:
        self.leases = {key: lease for key, lease in self.leases.items()
                       if lease["deadline"] > time.monotonic()}

    def acquire(self, actor: str, instance: str, surface: str) -> dict:
        self.authorize(actor, instance)
        self.prune()
        if any(lease["instance_id"] == instance for lease in self.leases.values()):
            raise Failure("audio_busy", "This source plays in another view. Stop it before moving playback.", 409)
        if len(self.leases) >= 16:
            raise Failure("capacity", "The active audio source limit was reached.", 409)
        identity = secrets.token_hex(16)
        self.leases[identity] = {"id": identity, "actor": actor, "instance_id": instance,
                                 "surface_id": surface, "deadline": time.monotonic() + 15}
        return {"id": identity, "expires_at": time.time() + 15}

    def current(self, identity: str, actor: str, surface: str) -> dict:
        self.prune()
        lease = self.leases.get(identity)
        if not lease or lease["actor"] != actor or lease["surface_id"] != surface:
            raise Failure("lease_expired", "Playback ownership expired. Select Play to acquire it again.", 409)
        return lease

    def heartbeat(self, identity: str, actor: str, surface: str) -> dict:
        lease = self.current(identity, actor, surface)
        try:
            self.authorize(actor, lease["instance_id"])
        except Failure:
            self.leases.pop(identity, None)
            raise
        lease["deadline"] = time.monotonic() + 15
        return {"id": identity, "expires_at": time.time() + 15}

    def release(self, identity: str, actor: str, surface: str) -> None:
        self.current(identity, actor, surface)
        self.leases.pop(identity, None)

    def preferences(self) -> dict:
        return self.service.store.get_setting("audio.preferences", {"revision": 0, "volume": 0.7, "muted": False})

    def save_preferences(self, body) -> dict:
        with self.service.store.lock, self.service.store.db:
            WorkspaceStore.revision(self.preferences(), body.revision)
            value = {**body.model_dump(), "revision": body.revision + 1}
            self.service.store.db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (
                "audio.preferences", json.dumps(value)))
        return value
