# SPDX-License-Identifier: Apache-2.0
"""Authorize registered roots and coordinate confirmed file actions."""

import asyncio
import base64
import copy
import json
import secrets
import time
from pathlib import Path

from ficc_node.file_access import FileError, new_name
from ficc_node.job_state import digest

from .errors import Failure
from .file_refs import References
from .file_store import FileStore, key_check
from .file_transport import FileTransport

ACTION_SCOPE = {"mkdir": "files:write", "rename": "files:write", "mode": "files:mode", "delete": "files:delete"}


class Files:
    def __init__(self, service):
        self.service = service
        self.store = FileStore(service.store)
        self.refs = References(service.store)
        self.transport = FileTransport(service)
        self.previews: dict[str, dict] = {}
        self.admission = asyncio.Lock()
        self.tasks: set[asyncio.Task] = set()
        self.root_locks: dict[str, asyncio.Lock] = {}
        if service.store.get_setting("controller_id", None) is None:
            service.store.set_setting("controller_id", secrets.token_hex(16))

    def registered(self):
        return self.store.roots()

    async def register(self, path, label, node_id=None, read_only=False):
        self.service.live()
        if not isinstance(path, str) or not Path(path).is_absolute() or not 1 <= len(label) <= 80:
            raise Failure("invalid_root", "Select an absolute directory path and a short label.")
        async with self.admission:
            value = {"id": secrets.token_hex(16), "path": path, "label": label, "node_id": node_id,
                     "read_only": bool(read_only), "revision": secrets.token_hex(16)}
            if node_id:
                node = self.service.store.node(node_id)
                value["fingerprint"] = node["fingerprint"]
            result, _ = await self.transport.call(value, {"action": "file.root"})
            value.update(identity=result["identity"], reference=result["reference"], mode_supported=result["mode_supported"])
            if any(root["node_id"] == node_id and root["identity"] == value["identity"] for root in self.registered()):
                raise Failure("root_exists", "This directory is already registered.", 409)
            self.store.add_root(value)
            self.service.store.audit("root.register", value["id"])
            return value

    def unregister(self, root_id):
        self.service.live()
        self.store.root(root_id)
        transfers = getattr(self.service, "transfers", None)
        if self.active(root_id=root_id) or (transfers and transfers.active(root_id=root_id)):
            raise Failure("root_busy", "Resolve file operations and discard retained downloads or partials before removing this root.", 409)
        self.store.remove_root(root_id)
        self.service.store.audit("root.remove", root_id)
        return {"ok": True}

    def check(self, actor, scope, root):
        principal = self.service.auth.current(actor)
        principal.require(scope, root.get("node_id"), root["id"])
        if root.get("node_id") is None and principal.node_ids is not None:
            raise Failure("denied", "This credential does not permit controller file access.", 403)
        if scope != "files:read" and root.get("read_only"):
            raise Failure("read_only", "This root is read-only.", 403)
        current = self.store.root(root["id"])
        if current["revision"] != root["revision"]:
            raise Failure("root_changed", "The root registration changed.", 409)

    async def call(self, root, request, actor, scope="files:read", data=b"", timeout=15):
        return await self.transport.call(root, request, data,
                                         check=lambda: self.check(actor, scope, root), timeout=timeout)

    async def roots(self, actor):
        result = []
        for root in self.registered():
            actions = []
            for action in ("read", "write", "mode", "delete"):
                if action == "mode" and not root.get("mode_supported", False):
                    continue
                try:
                    self.check(actor, "files:" + action, root)
                    actions.append(action)
                except Failure:
                    pass
            if not actions:
                continue
            value = {key: root[key] for key in ("id", "node_id", "label", "revision")}
            value.update(actions=actions, available=True, error=None, entry_id=self.refs.issue(root, root["reference"]))
            try:
                await self.transport.call(root, {"action": "file.root"},
                                          check=lambda: self.check(actor, "files:" + actions[0], root))
            except Failure as exc:
                value.update(available=False, error={"code": exc.code, "message": exc.message})
            result.append(value)
        return {"roots": result}

    def resolve(self, root_id, entry_id, actor, scope="files:read"):
        root = self.store.root(root_id)
        self.check(actor, scope, root)
        return root, self.refs.resolve(root, entry_id)

    def entry_view(self, root, entry):
        return {**{key: value for key, value in entry.items() if key != "reference"},
                "entry_id": self.refs.issue(root, entry["reference"]), "root_id": root["id"]}

    async def stat(self, root, reference, actor, scope="files:read"):
        result, _ = await self.call(root, {"action": "file.stat", "entry": reference}, actor, scope)
        return result

    async def listing(self, body, actor):
        root, ref = self.resolve(body["root_id"], body["entry_id"], actor)
        cursor = None
        if body.get("cursor"):
            try:
                cursor = json.loads(base64.b64decode(body["cursor"], validate=True))
            except (ValueError, TypeError):
                raise Failure("invalid_cursor", "The listing cursor is invalid.") from None
        result, _ = await self.call(root, {"action": "file.list", "entry": ref, "cursor": cursor,
                                           "limit": body.get("limit", 100)}, actor)
        crumbs, _ = await self.call(root, {"action": "file.breadcrumbs", "entry": ref}, actor)
        return {"root_id": root["id"], "entry_id": body["entry_id"],
                "entries": [self.entry_view(root, item) for item in result["entries"]],
                "breadcrumbs": [{"name": item["name"], "entry_id": self.refs.issue(root, item["reference"])}
                                for item in crumbs["entries"]],
                "next_cursor": base64.b64encode(json.dumps(result["next_cursor"]).encode()).decode()
                if result["next_cursor"] else None}

    async def content_preview(self, body, actor):
        root, ref = self.resolve(body["root_id"], body["entry_id"], actor)
        result, _ = await self.call(root, {"action": "file.preview", "entry": ref, "limit": body["limit"]}, actor)
        return {**result, "entry_id": body["entry_id"], "revision": digest(ref["identity"])}

    async def preview(self, body, actor):
        self.service.live()
        action = body["action"]
        if action == "mode" and (type(body.get("mode")) is not int or not 0 <= body["mode"] <= 0o777):
            raise Failure("invalid_mode", "Use ordinary owner, group, and other mode bits.")
        scope = ACTION_SCOPE[action]
        root = self.store.root(body["root_id"])
        self.check(actor, scope, root)
        entries = body.get("entries", [])
        if action in {"mkdir", "rename"}:
            try:
                new_name(body.get("name"))
            except (FileError, UnicodeError) as exc:
                raise Failure("invalid_name", "Enter a valid file name.") from exc
            parent = self.refs.resolve(root, body["parent_id"])
            value = await self.stat(root, parent, actor, scope)
            if value["kind"] != "directory":
                raise Failure("invalid_parent", "Select a destination directory.")
        else:
            parent = None
        if (action == "mkdir" and entries) or (action == "rename" and len(entries) != 1) or (
                action in {"delete", "mode"} and not 1 <= len(entries) <= 64) or len(set(entries)) != len(entries):
            raise Failure("invalid_entries", "Select distinct entries within the action limit.")
        items = []
        for entry_id in entries or [None]:
            ref = self.refs.resolve(root, entry_id) if entry_id else None
            value = await self.stat(root, ref, actor, scope) if ref else {"name": body["name"], "kind": "directory", "size": 0}
            if ref and not ref["parts"]:
                raise Failure("root_action", "The registered root cannot be changed.")
            await self.call(root, {"action": "file.validate", "mutation": {"action": action,
                "entry": ref, "parent": parent, "name": body.get("name"), "mode": body.get("mode")}}, actor, scope)
            items.append({"id": secrets.token_hex(16), "entry_id": entry_id, "reference": ref, "name": value["name"],
                          "kind": value["kind"], "size": value["size"]})
        self.previews = {key: value for key, value in self.previews.items() if value["expires_at"] > time.time()}
        if len(self.previews) >= 64:
            raise Failure("capacity", "The file preview limit was reached.", 429)
        preview = {"preview_id": secrets.token_hex(16), "expires_at": time.time() + 120, "actor": actor,
                   "request": copy.deepcopy(body), "root": root, "parent": parent, "items": items,
                   "request_digest": digest(body)}
        self.previews[preview["preview_id"]] = preview
        return {"preview_id": preview["preview_id"], "expires_at": preview["expires_at"],
                "request_digest": preview["request_digest"], "action": action, "root_id": root["id"],
                "entries": [{key: value for key, value in item.items() if key != "reference"} for item in items],
                "effects": [f"{action.capitalize()} {len(items)} selected entries."], "count": len(items)}

    async def submit(self, preview_id, key, actor):
        self.service.live()
        key_check(key)
        async with self.admission:
            previous = self.store.existing(actor, key)
            if previous:
                if previous["preview_id"] != preview_id:
                    raise Failure("idempotency_conflict", "This key belongs to another file request.", 409)
                self.check(actor, ACTION_SCOPE[previous["action"]], previous["root"])
                return previous
            preview = self.previews.get(preview_id)
            if not preview or preview["actor"] != actor or preview["expires_at"] <= time.time():
                raise Failure("preview_expired", "Create a new file operation preview.", 409)
            body, root = preview["request"], preview["root"]
            self.check(actor, ACTION_SCOPE[body["action"]], root)
            value = {**copy.deepcopy(preview), "id": secrets.token_hex(16), "key": key, "state": "queued",
                     "action": body["action"], "created_by": actor, "policy_revision": 1,
                     "created_at": time.time(), "updated_at": time.time()}
            for item in value["items"]:
                item.update(state="queued", result=None, error=None)
            self.store.insert(value)
            self.service.store.audit("file." + body["action"], value["id"], "queued", actor)
            task = asyncio.create_task(self.execute(value["id"]))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            return value

    async def execute(self, operation_id):
        value = self.store.get(operation_id)
        lock = self.root_locks.setdefault(value["root"]["id"], asyncio.Lock())
        async with lock:
            for item in value["items"]:
                if item["state"] == "succeeded":
                    continue
                try:
                    self.check(value["actor"], ACTION_SCOPE[value["action"]], value["root"])
                    item["state"] = "dispatching"
                    self.store.save(value)
                    mutation = {"action": value["action"], "entry": item["reference"], "parent": value["parent"],
                                "name": value["request"].get("name"), "mode": value["request"].get("mode")}
                    result, _ = await self.call(value["root"], {"action": "file.mutate", "operation_id": item["id"],
                                                               "mutation": mutation}, value["actor"], ACTION_SCOPE[value["action"]])
                    item.update(state=result["state"], result=result.get("result"))
                except Failure as exc:
                    item.update(state="unknown" if item["state"] == "dispatching" else "failed",
                                error={"code": exc.code, "message": exc.message})
                self.store.save(value)
            value["state"] = "succeeded" if all(item["state"] == "succeeded" for item in value["items"]) else "unknown" if any(
                item["state"] == "unknown" for item in value["items"]) else "failed"
            self.store.save(value)
            self.service.store.audit("file." + value["action"], value["id"], value["state"], value["actor"])

    def view(self, value, actor):
        self.check(actor, ACTION_SCOPE[value["action"]] if value["actor"] == actor else "files:read", value["root"])
        return {**{key: value[key] for key in ("id", "state", "action", "created_at", "updated_at")},
                "items": [{key: item[key] for key in ("id", "entry_id", "name", "state", "result", "error")}
                          for item in value["items"]]}

    def active(self, node_id=None, root_id=None):
        return any(value["state"] not in {"succeeded", "failed"} and
                   (node_id is None or value["root"].get("node_id") == node_id) and
                   (root_id is None or value["root"]["id"] == root_id) for value in self.store.iterate())

    async def poll(self):
        for value in self.store.iterate():
            if value["state"] == "queued" or any(item["state"] == "dispatching" for item in value["items"]):
                await self.execute(value["id"])
        await asyncio.Event().wait()

    async def reconcile(self, operation_id, actor):
        value = self.store.get(operation_id)
        self.check(actor, ACTION_SCOPE[value["action"]], value["root"])
        value["actor"] = actor
        self.store.save(value)
        await self.execute(operation_id)
        return self.view(self.store.get(operation_id), actor)

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
