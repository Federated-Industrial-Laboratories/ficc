# SPDX-License-Identifier: Apache-2.0
"""Coordinate bounded enrollment and independent resource polling."""

import asyncio
import random
import secrets
import sqlite3
import time

from .auth import Auth
from .errors import Failure
from .settings import MAX_NODES, Settings
from .ssh import SSH
from .store import Store

PUBLIC_FIELDS = {"id", "name", "profile", "host", "account", "fingerprint", "state",
                 "last_seen", "capabilities", "resources", "error"}


class Service:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.store = Store(settings.state_dir / "state.sqlite3")
        self.auth = Auth(self.store)
        self.ssh = SSH(settings)
        self.previews: dict[str, dict] = {}
        self.workers = asyncio.Semaphore(16)
        self.connections = asyncio.Semaphore(4)
        self.locks: dict[str, asyncio.Lock] = {}
        self.enrollment = asyncio.Lock()
        self.poll_error = False
        saved = self.store.get_setting("profiles", [])
        self.profiles = sorted(set(saved) | set(settings.profiles))
        self.store.set_setting("profiles", self.profiles)
        if not settings.demo and self.store.get_setting("demo", False):
            raise ValueError("Live mode requires a separate state directory.")
        if settings.demo:
            self.seed_demo()

    def seed_demo(self) -> None:
        if self.store.nodes():
            if not self.store.get_setting("demo", False):
                raise ValueError("Demo mode requires a separate state directory.")
            return
        self.store.set_setting("demo", True)
        for index, state in enumerate(("ready", "degraded", "unreachable")):
            seen = time.time() - (2 if index == 0 else 90)
            self.store.save_node({"id": f"demo-{index + 1}", "name": f"Lab machine {index + 1}",
                                 "profile": f"demo-{index + 1}", "host": f"machine-{index + 1}.example",
                                 "account": "operator", "fingerprint": "Simulated host identity",
                                 "state": state, "last_seen": seen,
                                 "capabilities": {"resources": True, "simulated": True},
                                 "error": None if index == 0 else {
                                     "code": "sample_stale", "message": "Simulated stale connection."},
                                 "resources": {"cpu_percent": 18.0 + index * 24, "cpu_count": 8,
                                               "load": [1.2, 1.0, 0.8],
                                               "memory_total_bytes": 34359738368,
                                               "memory_available_bytes": 17179869184,
                                               "uptime_seconds": 86400.0,
                                               "storage": [{"mount": "/", "total_bytes": 512000000000,
                                                            "available_bytes": 320000000000}],
                                               "network": [], "gpus": [], "gpu_status": "unsupported"}})

    def live(self) -> None:
        if self.settings.demo:
            raise Failure("demo_read_only", "Live changes are disabled in the simulated console.", 403)

    def authorize(self, actor: str, scope: str, node_id: str | None = None) -> None:
        value = self.auth.current(actor)
        value.require(scope, node_id)
        if scope == "nodes:write" and value.node_ids is not None:
            raise Failure("denied", "An unrestricted credential is required.", 403)

    def view(self, node: dict) -> dict:
        result = {key: node[key] for key in PUBLIC_FIELDS}
        if self.settings.demo and node["id"] == "demo-1":
            result["last_seen"] = time.time() - 2
        age = max(0.0, time.time() - result["last_seen"]) if result["last_seen"] else None
        result["sample_age_seconds"] = age
        result["stale"] = age is None or age > self.settings.stale_after
        if result["stale"] and result["state"] == "ready":
            result["state"] = "degraded"
        return result

    async def preview(self, profile: str, name: str, actor: str) -> dict:
        self.live()
        if profile not in self.profiles:
            raise Failure("profile_denied", "Select an approved local SSH profile.", 403)
        self.previews = {key: value for key, value in self.previews.items()
                         if value["expires_at"] > time.time()}
        if len(self.previews) >= MAX_NODES or self.connections.locked():
            raise Failure("capacity", "The connection queue is full.", 429)
        async with self.connections:
            def check():
                self.authorize(actor, "nodes:write")
            check()
            value = await self.ssh.preview(profile, name, check=check)
        value["preview_id"] = secrets.token_hex(16)
        value["actor"] = actor
        self.previews[value["preview_id"]] = value
        return {key: val for key, val in value.items() if key not in {"key", "key_type", "port", "actor"}}

    async def enroll(self, preview_id: str, expected: str, install: bool, actor: str) -> dict:
        self.live()
        async with self.enrollment:
            def check():
                self.authorize(actor, "nodes:write")
            check()
            preview = self.previews.get(preview_id)
            if preview is None or preview["expires_at"] <= time.time() or preview["actor"] != actor:
                raise Failure("preview_expired", "Create a new enrollment preview.", 409)
            if preview["trust"] != "trusted" or preview["fingerprint"] != expected:
                raise Failure("untrusted_host", "The expected key must match a trusted host key.", 409)
            if preview["helper_install_required"] and not install:
                raise Failure("helper_consent_required", "Select helper installation to continue.", 409)
            nodes = self.store.nodes()
            if len(nodes) >= MAX_NODES:
                raise Failure("capacity", "The machine limit was reached.", 409)
            if any(node["profile"] == preview["profile"] for node in nodes):
                raise Failure("already_enrolled", "This SSH profile is already enrolled.", 409)
            self.previews.pop(preview_id)
            node = {**preview, "id": secrets.token_hex(16), "state": "connecting", "last_seen": None,
                    "capabilities": {}, "resources": None, "error": None}
            self.store.audit("node.enroll", node["id"], "requested", actor=actor)
            try:
                if preview["helper_install_required"]:
                    async with self.connections:
                        check()
                        await self.ssh.install(node, check=check)
                check()
                self.store.save_node(node)
                result = (await self.refresh([node["id"]]))[0]
            except Failure:
                self.store.audit("node.enroll", node["id"], "failed", actor=actor)
                raise
            self.store.audit("node.enroll", node["id"], result["state"], actor=actor)
            return result

    async def refresh(self, node_ids: list[str], actor: str | None = None) -> list[dict]:
        self.live()
        if len(node_ids) > MAX_NODES or len(set(node_ids)) != len(node_ids):
            raise Failure("invalid_nodes", "Select distinct machines within the limit.")
        nodes = [self.store.node(node_id) for node_id in node_ids]

        async def one(node: dict) -> dict:
            lock = self.locks.setdefault(node["id"], asyncio.Lock())
            if lock.locked():
                return self.view(self.store.node(node["id"]))
            async with lock, self.workers:
                def check():
                    if actor:
                        self.authorize(actor, "nodes:read", node["id"])
                        self.authorize(actor, "resources:read", node["id"])
                check()
                try:
                    sample = await self.ssh.probe(node, check=check)
                    if sample is None:
                        raise Failure("helper_missing", "The node helper is unavailable.", 502)
                    node.update(resources=sample["resources"], capabilities=sample["capabilities"],
                                last_seen=time.time(), state="ready", error=None,
                                boot_id=sample["boot_id"], observed_at=sample["observed_at"],
                                sequence=node.get("sequence", 0) + 1)
                except Failure as exc:
                    state = exc.code if exc.code in {"host_key_changed", "authentication_failed", "unreachable"} else "degraded"
                    node.update(state=state, error={"code": exc.code, "message": exc.message})
                try:
                    self.store.node(node["id"])
                except Failure:
                    return self.view(node)
                self.store.save_node(node)
                return self.view(node)

        return await asyncio.gather(*(one(node) for node in nodes))

    async def poll(self) -> None:
        if self.settings.demo:
            return
        while True:
            try:
                await self.refresh([node["id"] for node in self.store.nodes()])
                self.poll_error = False
            except (Failure, sqlite3.Error):
                self.poll_error = True
            await asyncio.sleep(self.settings.poll_interval * random.uniform(0.9, 1.1))
