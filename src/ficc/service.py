# SPDX-License-Identifier: Apache-2.0
"""Coordinate bounded enrollment and independent resource polling."""

import asyncio
import random
import secrets
import sqlite3
import time
from contextlib import ExitStack, asynccontextmanager

from .agents import Agents
from .audio_sessions import AudioSessions
from .auth import Auth
from .bus import Bus
from .errors import Failure
from .files import Files
from .identity_store import LOCAL_OWNER
from .jobs import Jobs
from .module_adapter_vm import AdapterVMs
from .module_adapters import Adapters
from .module_admin import Administration
from .module_containers import Containers
from .module_proxmox import Proxmox
from .module_vm import VMs
from .module_vm_hosts import VMHosts
from .module_windows import WindowsEndpoints
from .modules import Registry
from .modules.runtime import Runtime
from .policies import Policies
from .settings import MAX_NODES, Settings
from .ssh import SSH
from .state_lock import StateLock
from .store import Store
from .terminals import Terminals
from .transfers import Transfers
from .viewer_sessions import Viewers
from .workspace_store import WorkspaceStore

PUBLIC_FIELDS = {"id", "name", "profile", "host", "account", "fingerprint", "state",
                 "last_seen", "capabilities", "resources", "error"}


class Service:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.state_lock = StateLock(settings.state_dir)
        try:
            pending = settings.state_dir / "archive.pending.json"
            if pending.exists() or pending.is_symlink():
                raise ValueError("History archival is incomplete. Resume archive-history with the same output directory before starting FICC.")
            self.initialize(settings)
        except BaseException:
            if hasattr(self, "remote_auth"):
                self.remote_auth.close()
            if hasattr(self, "contributors"):
                self.contributors.close()
            if hasattr(self, "policies"):
                self.policies.close()
            if hasattr(self, "workloads"):
                self.workloads.close()
            if hasattr(self, "store"):
                self.store.close()
            self.state_lock.close()
            raise

    def close(self) -> None:
        with ExitStack() as cleanup:
            for close in (self.state_lock.close, self.store.close, self.policies.close,
                          self.remote_auth.close, self.contributors.close, self.workloads.close, self.ssh.reset):
                cleanup.callback(close)

    def initialize(self, settings: Settings) -> None:
        self.store = Store(settings.state_dir / "state.sqlite3")
        from .audit_delivery import Delivery
        self.audit_delivery = Delivery(self)
        self.auth = Auth(self.store)
        from .contributors import Contributors
        self.contributors = Contributors(self)
        from .remote_auth import RemoteAuth
        self.remote_auth = RemoteAuth(self)
        self.policies = Policies(self)
        self.auth.policy_check = self.policies.check
        from .workloads.queue import Queue
        self.workloads = Queue(self)
        self.modules = Registry(self.store, settings.state_dir / "modules")
        self.module_runtime = Runtime(self.modules)
        self.workspaces = WorkspaceStore(self.store)
        self.audio = AudioSessions(self)
        self.jobs = Jobs(self)
        self.ssh = SSH(settings)
        self.auth.on_revoke = self.revoke_observers
        self.terminals = Terminals(self)
        self.files = Files(self)
        self.vms = VMs(self)
        self.proxmox = Proxmox(self)
        self.windows = WindowsEndpoints(self)
        self.adapters = Adapters(self, windows=self.windows)
        self.adapter_vms = AdapterVMs(self)
        self.vm_providers = VMHosts(self)
        self.containers = Containers(self)
        self.administration = Administration(self)
        self.viewers = Viewers(self)
        self.transfers = Transfers(self)
        from .datasets import Datasets
        self.datasets = Datasets(self)
        from .inspections import Inspections
        self.inspections = Inspections(self)
        from .sources import Sources
        self.sources = Sources(self)
        self.bus = Bus(self)
        self.agents = Agents(self)
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

    def revoke_observers(self, subject_id: str, node_ids: list[str] | None) -> None:
        # Observation connections belong to the local owner until machine access has project boundaries.
        if subject_id == LOCAL_OWNER:
            for node_id in [None] if node_ids is None else node_ids:
                self.ssh.reset(node_id)

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

    def retained_history(self, node_id: str) -> bool:
        if any(value["node_id"] == node_id for table in ("agents", "agent_profiles")
               for value in self.agents.store.all(table)):
            return True
        if any(target["node_id"] == node_id for operation in self.jobs.store.all()
               for target in operation["targets"]):
            return True
        if any(value["node_id"] == node_id for value in self.terminals.all()):
            return True
        if any(value["root"].get("node_id") == node_id for value in self.files.store.iterate()):
            return True
        return any(endpoint["root"].get("node_id") == node_id
                   for operation in self.transfers.store.iterate() for item in operation["items"]
                   for endpoint in (item["destination"], item.get("source")) if endpoint)

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
                return await self.observe(node, check)

        results = await asyncio.gather(*(one(node) for node in nodes))
        if actor:
            for node in nodes:
                self.authorize(actor, "nodes:read", node["id"])
                self.authorize(actor, "resources:read", node["id"])
        return results

    async def observe(self, node: dict, check) -> dict:
        try:
            sample = await self.ssh.probe(node, check=check)
            if sample is None:
                raise Failure("helper_missing", "The node helper is unavailable.", 502)
            node.update(resources=sample["resources"], capabilities=sample["capabilities"],
                        last_seen=time.time(), state="ready", error=None,
                        boot_id=sample["boot_id"], observed_at=sample["observed_at"],
                        helper_version=sample["helper_version"], sequence=node.get("sequence", 0) + 1)
        except Failure as exc:
            if exc.status in (401, 403):
                raise
            status = exc.code if exc.code in {"host_key_changed", "authentication_failed", "unreachable"} else "degraded"
            node.update(state=status, error={"code": exc.code, "message": exc.message})
        try:
            self.store.node(node["id"])
        except Failure:
            return self.view(node)
        self.store.save_node(node)
        return self.view(node)

    @asynccontextmanager
    async def configuration(self, node_id: str):
        lock = self.locks.setdefault(node_id, asyncio.Lock())
        async with (self.enrollment, self.jobs.admission, self.files.admission,
                    self.transfers.admission, self.agents.lock, self.terminals.lock, lock):
            yield

    async def upgrade(self, node_id: str, expected: str, actor: str) -> dict:
        self.live()
        async with self.configuration(node_id):
            def check():
                self.authorize(actor, "nodes:write", node_id)
            check()
            node = self.store.node(node_id)
            if node["fingerprint"] != expected:
                raise Failure("host_key_changed", "The expected fingerprint does not match the enrolled machine.", 409)
            if (self.agents.busy(node_id) or self.jobs.store.active(node_id) or self.terminals.busy(node_id)
                    or self.files.active(node_id=node_id) or self.transfers.active(node_id=node_id)):
                raise Failure("node_busy", "Resolve active or unknown work before upgrading the helper.", 409)
            self.store.audit("helper.upgrade", node_id, "requested", actor)
            self.ssh.reset(node_id)
            try:
                async with self.connections:
                    await self.ssh.install(node, check=check)
                async with self.workers:
                    result = await self.observe(node, check)
                if self.store.node(node_id).get("helper_version") != "3" or result["error"]:
                    raise Failure("helper_upgrade_failed", "The upgraded helper could not be verified. Refresh and retry.", 502)
            except Failure:
                self.store.audit("helper.upgrade", node_id, "failed", actor)
                raise
            self.store.audit("helper.upgrade", node_id, result["state"], actor)
            return result

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
