# SPDX-License-Identifier: Apache-2.0
"""Persist terminal intents and revalidate authority before each attachment."""

import asyncio
import hashlib
import json
import secrets
import time

from .auth import Principal, digest
from .errors import Failure
from .ssh import PROBE, transport_failure

TERMINAL = {"exited", "interrupted", "stopped"}
PUBLIC = {"id", "node_id", "node_name", "account", "label", "mode", "state",
          "created_at", "updated_at", "error"}


class Terminals:
    def __init__(self, service):
        self.service = service
        self.store = service.store
        self.lock = asyncio.Lock()
        self.active: dict[str, asyncio.Task] = {}
        self.tickets: dict[str, dict] = {}
        self.controller = self.store.get_setting("terminal_controller", None)
        if self.controller is None:
            self.controller = secrets.token_hex(16)
            self.store.set_setting("terminal_controller", self.controller)
        with self.store.lock, self.store.db:
            self.store.db.execute("CREATE TABLE IF NOT EXISTS terminals "
                                  "(id TEXT PRIMARY KEY,actor TEXT,key TEXT,digest TEXT,value TEXT,"
                                  "UNIQUE(actor,key))")
        for value in self.all():
            if value["state"] not in TERMINAL and not (value["mode"] == "tmux" and value["state"] == "unknown"):
                value["state"] = "interrupted" if value["mode"] == "ephemeral" else "detached"
                self.save(value)

    def all(self) -> list[dict]:
        with self.store.lock:
            return [json.loads(row[0]) for row in self.store.db.execute(
                "SELECT value FROM terminals ORDER BY rowid DESC")]

    def get(self, terminal_id: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM terminals WHERE id=?", (terminal_id,)).fetchone()
        if row is None:
            raise Failure("not_found", "The terminal was not found.", 404)
        return json.loads(row[0])

    def save(self, value: dict) -> None:
        value["updated_at"] = time.time()
        with self.store.lock, self.store.db:
            self.store.db.execute("INSERT INTO terminals VALUES (?,?,?,?,?) ON CONFLICT(id) "
                                  "DO UPDATE SET value=excluded.value", (
                                      value["id"], value["actor"], value["key"], value["digest"], json.dumps(value)))

    def view(self, value: dict) -> dict:
        return {key: value[key] for key in PUBLIC}

    def check(self, actor: str, scope: str, value: dict) -> Principal:
        current = self.service.auth.current(actor)
        current.require(scope, value["node_id"])
        node = self.store.node(value["node_id"])
        if node["fingerprint"] != value["fingerprint"]:
            raise Failure("identity_changed", "The terminal machine identity changed.", 409)
        return current

    def busy(self, node_id: str) -> bool:
        return any(v["node_id"] == node_id and v["state"] not in TERMINAL for v in self.all())

    async def remote(self, value: dict, action: str, actor: str, scope: str) -> dict:
        request = {"version": "3", "action": "terminal." + action,
                   "controller_id": self.controller, "terminal_id": value["id"]}
        if action == "create":
            request.update(cols=value["cols"], rows=value["rows"])
        def check():
            self.check(actor, scope, value)
        check()
        node = self.store.node(value["node_id"])
        if node.get("helper_version") != "3":
            raise Failure("helper_upgrade_required", "Upgrade the node helper to use persistent terminals.", 409)
        async with self.service.connections:
            code, output, stderr = await self.service.ssh.command(
                node, PROBE, json.dumps(request).encode() + b"\n", check=check)
        try:
            result = json.loads(output)
            if code == 65 and result.get("error"):
                raise Failure("terminal_refused", "The node refused the terminal operation.", 409)
            if code:
                raise transport_failure(stderr)
            if result.get("version") != "3" or result["result"]["state"] not in {"detached", "missing", "stopped"}:
                raise ValueError()
            return result["result"]
        except (ValueError, KeyError, TypeError):
            raise Failure("invalid_terminal_response", "The terminal response is invalid.", 502) from None

    async def create(self, request: dict, actor: str) -> dict:
        self.service.live()
        key = request.pop("idempotency_key")
        fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        async with self.lock:
            self.service.authorize(actor, "terminals:execute", request["node_id"])
            for value in self.all():
                if (value["actor"], value["key"]) == (actor, key):
                    if value["digest"] != fingerprint:
                        raise Failure("idempotency_conflict", "The terminal request key is already in use.", 409)
                    return self.view(value)
            records = self.all()
            pending = [value for value in records if value["state"] not in TERMINAL]
            if len(records) >= 512 or len(pending) >= 16 or sum(
                value["node_id"] == request["node_id"] for value in pending
            ) >= 4:
                raise Failure("capacity", "The terminal session limit was reached.", 409)
            node = self.store.node(request["node_id"])
            if request["mode"] == "tmux" and not node["capabilities"].get("terminals_tmux"):
                raise Failure("unsupported", "Persistent terminals are unavailable on this machine.", 409)
            value = {**request, "id": secrets.token_hex(16), "actor": actor, "key": key,
                     "digest": fingerprint, "node_name": node["name"], "account": node["account"],
                     "fingerprint": node["fingerprint"], "state": "new", "created_at": time.time(), "error": None}
            self.save(value)
            self.store.audit("terminal.create", value["id"], "requested", actor)
            if value["mode"] == "tmux":
                try:
                    result = await self.remote(value, "create", actor, "terminals:execute")
                    value["state"] = "detached" if result["state"] == "detached" else "unknown"
                except Failure as exc:
                    value.update(state="unknown", error={"code": exc.code, "message": exc.message})
                except asyncio.CancelledError:
                    value["state"] = "unknown"
                    self.save(value)
                    raise
                self.save(value)
            return self.view(value)

    def ticket(self, terminal_id: str, actor: str) -> dict:
        self.service.live()
        value = self.get(terminal_id)
        self.check(actor, "terminals:execute", value)
        if value["state"] in TERMINAL:
            raise Failure("terminal_closed", "This terminal session is closed.", 409)
        self.tickets = {key: row for key, row in self.tickets.items() if row["expires_at"] > time.time()}
        if len(self.tickets) >= 128:
            raise Failure("capacity", "The terminal ticket limit was reached.", 429)
        token, expiry = secrets.token_urlsafe(32), time.time() + 30
        self.tickets[digest(token)] = {"actor": actor, "terminal_id": terminal_id, "expires_at": expiry}
        return {"ticket": token, "expires_at": expiry,
                "websocket_path": f"/api/v1/terminals/{terminal_id}/stream"}

    def consume(self, terminal_id: str, token: str) -> str:
        if not isinstance(token, str) or len(token) > 128:
            raise Failure("denied", "The terminal ticket is invalid.", 403)
        ticket = self.tickets.pop(digest(token), None)
        if ticket is None or ticket["terminal_id"] != terminal_id or ticket["expires_at"] <= time.time():
            raise Failure("denied", "The terminal ticket is invalid or expired.", 403)
        self.check(ticket["actor"], "terminals:execute", self.get(terminal_id))
        return ticket["actor"]

    async def arguments(self, value: dict, actor: str) -> list[str]:
        if value["mode"] == "tmux":
            result = await self.remote(value, "status", actor, "terminals:execute")
            if result["state"] != "detached":
                value["state"] = "exited"
                self.save(value)
                raise Failure("terminal_closed", "The remote session no longer exists.", 409)
        args = await self.service.ssh.arguments(self.store.node(value["node_id"]), terminal=True)
        self.check(actor, "terminals:execute", value)
        if value["mode"] == "tmux":
            args.append('exec python3 "$HOME/.local/lib/ficc/node.pyz" --attach-terminal '
                        + self.controller + " " + value["id"])
        return args

    async def stop(self, terminal_id: str, actor: str) -> dict:
        self.service.live()
        async with self.lock:
            value = self.get(terminal_id)
            self.check(actor, "terminals:stop", value)
            if value["state"] == "stopped":
                return self.view(value)
            value["state"] = "unknown"
            self.save(value)
            self.store.audit("terminal.stop", terminal_id, "requested", actor)
            task = self.active.get(terminal_id)
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            value = self.get(terminal_id)
            if value["mode"] == "tmux":
                try:
                    await self.remote(value, "stop", actor, "terminals:stop")
                except Failure as exc:
                    value.update(state="unknown", error={"code": exc.code, "message": exc.message})
                    self.save(value)
                    return self.view(value)
            value.update(state="stopped", error=None)
            self.save(value)
            self.store.audit("terminal.stop", terminal_id, actor=actor)
            return self.view(value)

    async def reconcile(self, terminal_id: str, actor: str) -> dict:
        self.service.live()
        async with self.lock:
            value = self.get(terminal_id)
            self.check(actor, "terminals:execute", value)
            if value["mode"] != "tmux" or value["state"] != "unknown":
                return self.view(value)
            result = await self.remote(value, "status", actor, "terminals:execute")
            value.update(state="detached" if result["state"] == "detached" else "exited", error=None)
            self.save(value)
            self.store.audit("terminal.reconcile", terminal_id, value["state"], actor)
            return self.view(value)

    async def close(self) -> None:
        tasks = list(self.active.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.tickets.clear()
