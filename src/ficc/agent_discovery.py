# SPDX-License-Identifier: Apache-2.0
"""Poll enrolled machines and reconcile their discovered agent registrations."""

import asyncio
import sqlite3
import time
from pathlib import PurePosixPath

from .agent_schema import DiscoveryResult
from .agent_store import fingerprint
from .errors import Failure


class Discovery:
    def __init__(self, manager):
        self.manager = manager
        self.service = manager.service
        self.locks = {}
        self.slots = asyncio.Semaphore(2)
        self.due = {}
        self.last_attempt = {}
        self.status = self.service.store.get_setting("agent_discovery", {})
        self.failed = False
        self.tasks = {}

    def view(self, node):
        return {"node_id": node["id"], "node": {key: node[key] for key in ("id", "name", "account", "host", "profile")},
                **self.status.get(node["id"], {"state": "pending", "checked_at": None, "errors": []})}

    def save_status(self, node_id, **values):
        self.status[node_id] = values
        enrolled = {node["id"] for node in self.service.store.nodes()}
        self.status = {key: value for key, value in self.status.items() if key in enrolled}
        self.service.store.set_setting("agent_discovery", self.status)

    def forget(self, node_id):
        # Called under the node configuration lock after all retained work checks.
        for profile in self.manager.store.all("agent_profiles"):
            if profile["node_id"] == node_id and profile.get("source") == "discovered":
                self.manager.store.delete("agent_profiles", profile["id"])
        task = self.tasks.pop(node_id, None)
        if task and not task.done():
            task.cancel()
        self.status.pop(node_id, None)
        self.service.store.set_setting("agent_discovery", self.status)
        self.due.pop(node_id, None)
        self.last_attempt.pop(node_id, None)

    async def refresh(self, actor=None, *, force=True):
        self.service.live()
        nodes = self.service.store.nodes()
        if actor:
            principal = self.service.auth.current(actor)
            principal.require("agents:read")
            nodes = [node for node in nodes if principal.permits("agents:read", node["id"])]
        selected = []
        for node in nodes:
            task = self.tasks.get(node["id"])
            if task is None or task.done():
                self.tasks.pop(node["id"], None)
                if task and not task.cancelled():
                    task.result()
                task = asyncio.create_task(self.scan(node, actor, force=force))
                self.tasks[node["id"]] = task
            selected.append(task)
        if selected:
            completed, _ = await asyncio.wait(selected, timeout=2)
            for task in completed:
                if not task.cancelled():
                    task.result()
        if actor:
            for node in nodes:
                self.service.authorize(actor, "agents:read", node["id"])
        return [self.view(node) for node in self.service.store.nodes() if any(n["id"] == node["id"] for n in nodes)]

    async def scan(self, node, actor=None, *, force=True):
        identity = node["id"]
        async with self.locks.setdefault(identity, asyncio.Lock()):
            now = time.monotonic()
            if force and now - self.last_attempt.get(identity, -60) < 2:
                return
            if not force and now < self.due.get(identity, 0):
                return
            self.last_attempt[identity] = now
            self.due[identity] = now + 60
            if not node["capabilities"].get("agent_discovery"):
                self.due.pop(identity, None)
                if self.status.get(identity, {}).get("state") != "unsupported":
                    self.save_status(identity, state="unsupported", checked_at=None, errors=[],
                                     message="Upgrade this machine's FICC helper to discover installed agents.")
                return
            def check():
                if actor:
                    self.service.authorize(actor, "agents:read", identity)
            try:
                check()
                self.save_status(identity, **{**self.status.get(identity, {}), "state": "scanning"})
                async with self.slots:
                    raw = await self.manager.remote(identity, "discover", {}, check)
                check()
                result = DiscoveryResult.model_validate(raw).model_dump()
                commands = [item["command"] for item in result["profiles"]]
                if len(commands) != len(set(commands)):
                    raise ValueError("Duplicate discovered commands.")
                for item in result["profiles"]:
                    if not PurePosixPath(item["argv"][0]).is_absolute() or not PurePosixPath(item["workspace"]).is_absolute():
                        raise ValueError("Discovered paths must be absolute.")
                async with self.service.configuration(identity):
                    check()
                    current = self.service.store.node(identity)
                    if current["fingerprint"] != node["fingerprint"]:
                        raise Failure("identity_changed", "The machine identity changed during discovery.", 409)
                    self.reconcile(node, result["profiles"])
                    self.save_status(identity, state="ready", checked_at=time.time(),
                                     count=len(commands), errors=result["errors"])
            except Failure as exc:
                if exc.status in (401, 403):
                    # The initiating credential cannot authorize persistence, but
                    # its failure must not revoke another caller sharing the scan.
                    self.due.pop(identity, None)
                    self.last_attempt.pop(identity, None)
                    self.save_status(identity, state="pending", checked_at=None, errors=[])
                    return
                self.save_status(identity, state="error", checked_at=time.time(), errors=[], message=exc.message)
            except (ValueError, OSError):
                self.save_status(identity, state="error", checked_at=time.time(), errors=[],
                                 message="The machine's installed agents could not be verified. Refresh agents to retry.")

    def reconcile(self, node, discovered):
        store = self.manager.store
        saved = [item for item in store.all("agent_profiles") if item["node_id"] == node["id"]]
        automatic = {item["command"]: item for item in saved if item.get("source") == "discovered"}
        manual = [item for item in saved if item.get("source") != "discovered"]
        seen = set()
        for item in discovered:
            command = item["command"]
            # An explicit workspace registration already exposes this exact runtime.
            if any(all(existing.get(key) == item[key] for key in ("argv", "adapter", "version", "delivery_method"))
                   and existing["fingerprint"] == node["fingerprint"] for existing in manual):
                continue
            seen.add(command)
            fields = {**item, "node_id": node["id"], "fingerprint": node["fingerprint"],
                      "source": "discovered", "availability": "available"}
            revision = fingerprint(fields)
            value = automatic.get(command)
            if value is None:
                value = store.new("agent_profiles", "local-owner", "discovered-" + node["id"] + "-" + command, fields)
            value.update(**fields, discovery_revision=revision, verified_at=time.time())
            store.save("agent_profiles", value)
        for command, value in automatic.items():
            if command not in seen and value.get("availability") != "unavailable":
                value.update(availability="unavailable", verified_at=time.time())
                store.save("agent_profiles", value)

    async def poll(self):
        if self.service.settings.demo:
            return
        try:
            while True:
                try:
                    await self.refresh(force=False)
                    self.failed = False
                except (Failure, sqlite3.Error):
                    self.failed = True
                await asyncio.sleep(5)
        finally:
            for task in self.tasks.values():
                task.cancel()
            await asyncio.gather(*self.tasks.values(), return_exceptions=True)
