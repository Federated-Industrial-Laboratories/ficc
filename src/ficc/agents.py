# SPDX-License-Identifier: Apache-2.0
"""Bind registered profiles, managed terminals and host-initiated agent exchange."""

import asyncio
import json
import secrets
import sqlite3
import time

from .agent_schema import Profile
from .agent_store import CLOSED, SETTLED, AgentStore, public
from .errors import Failure
from .ssh import PROBE, transport_failure
from .terminals import TERMINAL


class Agents:
    def __init__(self, service):
        self.service = service
        self.store = AgentStore(service.store)
        self.lock = asyncio.Lock()
        self.agent_locks = {}
        self.relay_slots = asyncio.Semaphore(2)
        self.previews = {}
        self.cursors = {}
        self.poll_error = False
        self.controller = service.store.get_setting("agent_controller", None)
        if self.controller is None:
            self.controller = secrets.token_hex(16)
            service.store.set_setting("agent_controller", self.controller)
        for value in self.store.all("agents"):
            if value["state"] not in CLOSED:
                value["state"] = "unknown"
                self.store.save("agents", value)

    def all(self):
        return self.store.all("agents")

    def busy(self, node_id):
        return (any(value["node_id"] == node_id and value["state"] not in CLOSED for value in self.all())
                or any(value["node_id"] == node_id and value["state"] not in SETTLED
                       for value in self.service.bus.deliveries()))

    async def remote(self, node_id, action, body, check=None):
        node = self.service.store.node(node_id)
        if node.get("helper_version") != "3" or not node["capabilities"].get("agents"):
            raise Failure("helper_upgrade_required", "Upgrade and refresh this node helper to use coding agents.", 409)
        def verify():
            current = self.service.store.node(node_id)
            if current["fingerprint"] != node["fingerprint"]:
                raise Failure("identity_changed", "The registered node identity changed.", 409)
            if check:
                check()
        request = {"version": "3", "action": "agent." + action, **body}
        raw = json.dumps(request, allow_nan=False).encode() + b"\n"
        if len(raw) > 131072:
            raise Failure("capacity", "The agent exchange exceeds its byte limit.", 409)
        async with self.service.connections:
            code, output, stderr = await self.service.ssh.command(node, PROBE, raw, check=verify)
        try:
            response = json.loads(output)
            if code == 65:
                raise Failure("agent_refused", str(response.get("error", "The node refused this agent operation."))[:240], 409)
            if code:
                raise transport_failure(stderr)
            if response.get("version") != "3" or not isinstance(response.get("result"), dict):
                raise ValueError()
            return response["result"]
        except (ValueError, KeyError, TypeError):
            raise Failure("invalid_agent_response", "The node agent response is invalid.", 502) from None

    async def register(self, request):
        self.service.live()
        try:
            value = Profile.model_validate(request).model_dump()
        except ValueError:
            raise Failure("invalid_profile", "The registered agent profile is invalid.") from None
        async with self.service.configuration(value["node_id"]):
            node = self.service.store.node(value["node_id"])
            verified = await self.remote(node["id"], "probe", {"profile": {key: value[key] for key in ("argv", "workspace", "adapter")}})
            profile = self.store.new("agent_profiles", "local-owner", secrets.token_hex(16), value,
                **value, version=verified["version"], delivery_method=verified["delivery_method"],
                fingerprint=node["fingerprint"], verified_at=time.time())
            profile["workspace"] = verified["workspace"]
            self.store.save("agent_profiles", profile)
            return public(profile)

    def remove_profile(self, identity):
        self.store.get("agent_profiles", identity)
        if any(value["profile_id"] == identity for value in self.all()):
            raise Failure("profile_retained", "Archive every retained run using this profile before removal.", 409)
        self.store.delete("agent_profiles", identity)
        return {"ok": True}

    def check(self, value, actor, scope):
        self.service.authorize(actor, scope, value["node_id"])
        node = self.service.store.node(value["node_id"])
        if node["fingerprint"] != value["fingerprint"]:
            raise Failure("identity_changed", "The saved agent node identity changed.", 409)

    async def preview(self, request, actor):
        self.service.live()
        profile = self.store.get("agent_profiles", request["profile_id"])
        self.check(profile, actor, "agents:execute")
        run = self.service.bus.check_run(request["run_id"], actor, "bus:send")
        if run["state"] != "open":
            raise Failure("run_closed", "Select an open bus run.", 409)
        verified = await self.remote(profile["node_id"], "probe", {
            "profile": {key: profile[key] for key in ("argv", "workspace", "adapter")}},
            lambda: self.check(profile, actor, "agents:execute"))
        if any(profile[key] != verified[key] for key in ("argv", "workspace", "adapter", "version", "delivery_method")):
            raise Failure("profile_changed", "Register the changed runtime profile again before launch.", 409)
        self.previews = {key: value for key, value in self.previews.items() if value["expires_at"] > time.time()}
        if len(self.previews) >= 64:
            raise Failure("capacity", "The agent preview limit was reached.", 429)
        preview = {"preview_id": secrets.token_hex(16), "expires_at": time.time() + 120,
                   "actor": actor, "profile": profile, "request": request,
                   "delivery_method": profile["delivery_method"],
                   "node": {key: self.service.store.node(profile["node_id"])[key] for key in ("id", "name", "account", "fingerprint")}}
        self.previews[preview["preview_id"]] = preview
        return {**public(preview), "profile": public(profile)}

    async def launch(self, request, actor):
        self.service.live()
        async with self.lock, self.service.terminals.lock:
            intent = {"preview_id": request["preview_id"], "confirm_execution": True}
            previous = self.store.retry("agents", actor, request["idempotency_key"], intent)
            if previous:
                self.check(previous, actor, "agents:execute")
                return public(previous)
            preview = self.previews.get(request["preview_id"])
            if preview is None or preview["expires_at"] <= time.time() or preview["actor"] != actor:
                raise Failure("preview_expired", "Create a new agent launch preview.", 409)
            profile = preview["profile"]
            self.check(profile, actor, "agents:execute")
            run = self.service.bus.check_run(preview["request"]["run_id"], actor, "bus:send")
            if run["state"] != "open":
                raise Failure("run_closed", "Select an open bus run.", 409)
            terminals = self.service.terminals.all()
            active = [value for value in terminals if value["state"] not in TERMINAL]
            if len(terminals) >= 512 or len(active) >= 16 or sum(value["node_id"] == profile["node_id"] for value in active) >= 4:
                raise Failure("capacity", "The managed terminal limit was reached.", 409)
            if len(self.all()) >= 512:
                raise Failure("capacity", "Archive a closed agent run before launching another agent.", 409)
            node = self.service.store.node(profile["node_id"])
            value = self.store.new("agents", actor, request["idempotency_key"], intent,
                **preview["request"], node_id=node["id"], node_name=node["name"],
                adapter=profile["adapter"], workspace=profile["workspace"], version=profile["version"],
                delivery_method=profile["delivery_method"], fingerprint=node["fingerprint"],
                terminal_id=secrets.token_hex(16), state="starting", runtime_session_id=None,
                last_contact=None, error=None, outbox_acks=[])
            terminal = {"id": value["terminal_id"], "actor": actor, "key": "agent-" + value["id"],
                "digest": value["digest"], "node_id": node["id"], "node_name": node["name"],
                "account": node["account"], "label": value["label"], "mode": "tmux", "cols": value["cols"],
                "rows": value["rows"], "fingerprint": node["fingerprint"], "state": "unknown",
                "created_at": time.time(), "error": None, "agent_id": value["id"]}
            self.store.save("agents", value)
            self.service.terminals.save(terminal)
            self.service.store.audit("agent.launch", value["id"], "requested", actor)
            spec = {"agent_id": value["id"], "controller_id": self.controller,
                "terminal_id": value["terminal_id"], "terminal_controller": self.service.terminals.controller,
                "run_id": value["run_id"], "profile": {key: profile[key] for key in ("argv", "workspace", "adapter")},
                "version": profile["version"], "delivery_method": profile["delivery_method"],
                "cols": value["cols"], "rows": value["rows"]}
            try:
                result = await self.remote(node["id"], "launch", {"controller_id": self.controller, "agent_id": value["id"], "spec": spec},
                                           lambda: self.check(value, actor, "agents:execute"))
                self.observed(value, result)
            except Failure as exc:
                value.update(state="unknown", error={"code": exc.code, "message": exc.message})
            except asyncio.CancelledError:
                value["state"] = "unknown"
                self.store.save("agents", value)
                raise
            self.store.save("agents", value)
            return public(value)

    def observed(self, value, result):
        if result.get("state") not in {"starting", "ready", "suspended", "unknown", "exited", "stopped"}:
            raise Failure("invalid_agent_response", "The runtime state is invalid.", 502)
        value.update({key: result.get(key) for key in ("state", "runtime_session_id", "observed_session_id", "last_contact")})
        value["error"] = None
        terminal = self.service.terminals.get(value["terminal_id"])
        if terminal["state"] != "attached":
            terminal["state"] = value["state"] if value["state"] in CLOSED else ("unknown" if value["state"] == "unknown" else "detached")
            self.service.terminals.save(terminal)

    async def action(self, identity, actor, action, extra=None):
        self.service.live()
        async with self.agent_locks.setdefault(identity, asyncio.Lock()):
            value = self.store.get("agents", identity)
            scope = "agents:stop" if action == "stop" else "agents:execute"
            self.check(value, actor, scope)
            if action == "stop" and value["state"] == "stopped":
                await self.close_terminal(value)
                return public(value)
            try:
                result = await self.remote(value["node_id"], action, {"controller_id": self.controller,
                    "agent_id": identity, **(extra or {})}, lambda: self.check(value, actor, scope))
                self.observed(value, result)
                if action == "stop":
                    self.store.save("agents", value)
                    self.service.bus.cancel_unsubmitted(identity)
                    await self.close_terminal(value)
            except Failure as exc:
                if action == "rebind" and exc.code == "agent_refused":
                    value["error"] = {"code": exc.code, "message": exc.message}
                    self.store.save("agents", value)
                    raise
                value.update(state="unknown", error={"code": exc.code, "message": exc.message})
            self.store.save("agents", value)
            return public(value)

    async def close_terminal(self, value):
        manager = self.service.terminals
        async with manager.lock:
            task = manager.active.get(value["terminal_id"])
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            terminal = manager.get(value["terminal_id"])
            terminal["state"] = value["state"]
            manager.save(terminal)

    async def exchange(self, value):
        from .agent_exchange import exchange
        await exchange(self, value)

    async def poll(self):
        if self.service.settings.demo:
            return
        async def one(identity):
            async with self.relay_slots, self.agent_locks.setdefault(identity, asyncio.Lock()):
                value = self.store.get("agents", identity)
                try:
                    await self.exchange(value)
                except (Failure, OSError, ValueError):
                    value["error"] = {"code": "agent_offline", "message": "The agent exchange could not be confirmed."}
                    self.store.save("agents", value)
        while True:
            try:
                unresolved = {d["agent_id"] for d in self.service.bus.deliveries() if d["state"] not in SETTLED}
                selected = [value["id"] for value in self.all()
                            if value["state"] not in CLOSED or value.get("outbox_acks") or value["id"] in unresolved]
                results = await asyncio.gather(*(one(identity) for identity in selected), return_exceptions=True)
                # Drain the whole batch before retrying a storage failure.
                for result in results:
                    if isinstance(result, BaseException) and not isinstance(result, sqlite3.Error):
                        raise result
                self.poll_error = any(isinstance(result, sqlite3.Error) for result in results)
            except sqlite3.Error:
                self.poll_error = True
            await asyncio.sleep(2)
