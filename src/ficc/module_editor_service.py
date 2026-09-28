# SPDX-License-Identifier: Apache-2.0
"""Bind editor requests to current instance, package, caller and folder grants."""

import asyncio
import hashlib
import re
import secrets
import time

from ficc_node.job_state import digest

from .errors import Failure
from .module_editor_store import EditorStore, retained


def contains_editor(node):
    if node.get("type") == "file-editor":
        return True
    return any(contains_editor(child) for child in node.get("children", [])) or any(
        contains_editor(child) for tab in node.get("items", []) if isinstance(tab, dict)
        for child in tab.get("children", []))


class Editor:
    def __init__(self, service):
        self.service, self.files = service, service.files
        self.store = EditorStore(service.store)
        self.admission = asyncio.Lock()

    def active(self, **filters):
        return retained(self.service.store, **filters)

    def context(self, actor, workspace_id, instance_id):
        self.service.auth.current(actor).require("workspaces:read")
        space = self.service.workspaces.get(workspace_id)
        instance = next((item for item in space["instances"] if item["id"] == instance_id), None)
        if instance is None:
            raise Failure("editor_instance", "The editor panel was not found.", 404)
        module = self.service.modules.get(instance["digest"])
        if not contains_editor(module["manifest"]["ui"]):
            raise Failure("editor_instance", "This module does not contain a file editor.", 403)
        self.service.modules.require(instance["digest"], "workspace:read", [workspace_id])
        return {"workspace_id": workspace_id, "instance_id": instance_id,
                "package_digest": instance["digest"], "targets": list(instance.get("targets", [])),
                "module_revision": module["revision"]}

    def check(self, actor, context, root, write=False):
        current = self.context(actor, context["workspace_id"], context["instance_id"])
        if current != context:
            raise Failure("editor_context_changed", "The editor package, targets or grants changed.", 409)
        if root["id"] not in context["targets"]:
            raise Failure("editor_target", "This folder is not selected for the editor panel.", 403)
        registered = self.files.store.root(root["id"])
        if any(registered.get(key) != root.get(key) for key in (
                "id", "revision", "path", "identity", "reference", "node_id", "fingerprint")):
            raise Failure("root_changed", "The root registration changed.", 409)
        scopes = ["files:read", "files:write"] if write else ["files:read"]
        for scope in scopes:
            self.service.modules.require(context["package_digest"], scope, [root["id"]])
            self.files.check(actor, scope, registered)
        if root.get("node_id") and self.service.store.node(root["node_id"])["fingerprint"] != root["fingerprint"]:
            raise Failure("root_changed", "The registered system identity changed.", 409)

    async def call(self, actor, context, root, action, write=False, data=b"", **values):
        def check():
            self.check(actor, context, root, write)
        check()
        result = await self.files.transport.call(root, {"action": action, **values}, data=data, check=check)
        try:
            check()
        except Failure as exc:
            if write:
                raise Failure("editor_authority_changed", "Access changed after dispatch. Restore access and check the save outcome.", 403) from exc
            raise
        return result

    async def roots(self, actor, workspace_id, instance_id):
        context = self.context(actor, workspace_id, instance_id)
        roots = []
        for identity in context["targets"]:
            try:
                root = self.files.store.root(identity)
                self.check(actor, context, root)
                writable = True
                try:
                    self.check(actor, context, root, True)
                except Failure:
                    writable = False
                roots.append({"id": root["id"], "label": root["label"], "node_id": root["node_id"],
                              "entry_id": self.files.refs.issue(root, root["reference"]), "writable": writable})
            except Failure as exc:
                if exc.status not in (403, 404):
                    raise
        return {"roots": roots}

    async def listing(self, actor, body):
        context = self.context(actor, body["workspace_id"], body["instance_id"])
        root = self.files.store.root(body["root_id"])
        self.check(actor, context, root)
        result = await self.files.listing({key: body[key] for key in ("root_id", "entry_id", "cursor")}, actor)
        self.check(actor, context, root)
        return result

    async def read(self, actor, body):
        context = self.context(actor, body["workspace_id"], body["instance_id"])
        results, used, checked = [], 0, []
        for item in body["items"]:
            try:
                root = self.files.store.root(item["root_id"])
                self.check(actor, context, root)
                entry = self.files.refs.resolve(root, item["entry_id"])
                value, data = await self.call(actor, context, root, "editor.read", entry=entry)
                if len(data) > 262144 or hashlib.sha256(data).hexdigest() != value.get("sha256") or used + len(data) > 524288:
                    raise Failure("editor_limit", "The text batch exceeds its byte limit or content check.", 409)
                text = data.decode("utf-8")
                if "\0" in text:
                    raise Failure("editor_text", "The file is not plain UTF-8 text.", 409)
                used += len(data)
                writable = value.get("editable", False)
                try:
                    self.check(actor, context, root, True)
                except Failure:
                    writable = False
                results.append({**item, "data": {**value, "text": text, "writable": writable}})
                checked.append(root)
            except (Failure, UnicodeError) as exc:
                results.append({**item, "error": self.error(exc)})
        for root in checked:
            self.check(actor, context, root)
        self.context(actor, body["workspace_id"], body["instance_id"])
        return {"results": results}

    @staticmethod
    def error(exc):
        return {"code": getattr(exc, "code", "editor_text"),
                "message": getattr(exc, "message", "The file is not UTF-8 text.")}

    @staticmethod
    def state(value):
        states = {item["state"] for item in value["items"]}
        return "unknown" if states & {"pending", "unknown"} else "conflict" if "conflict" in states else "failed" if "failed" in states else "succeeded"

    def record_context(self, actor, body):
        value = self.store.get(body["operation_id"])
        context = self.context(actor, body["workspace_id"], body["instance_id"])
        if any(value[key] != context[key] for key in ("workspace_id", "instance_id", "package_digest", "targets")):
            raise Failure("editor_context_changed", "This receipt belongs to another editor configuration.", 409)
        for item in value["items"]:
            self.check(actor, context, item["root"])
        return value, context

    def public(self, value):
        items = []
        for item in value["items"]:
            result = {key: item.get(key) for key in ("id", "root_id", "entry_id", "state", "retained", "resolved", "message", "error")}
            receipt = item.get("receipt", {})
            if receipt.get("reference") and item["state"] == "succeeded":
                result["entry_id"] = self.files.refs.issue(item["root"], receipt["reference"])
                result["sha256"] = receipt["sha256"]
            items.append(result)
        return {"id": value["id"], "state": value["state"], "items": items,
                "created_at": value["created_at"], "updated_at": value["updated_at"]}

    async def save(self, actor, body, key):
        if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{32}", key):
            raise Failure("editor_key", "Supply a 32-character hexadecimal Idempotency-Key.")
        if body.get("accept_retained_exchange") is not True:
            raise Failure("confirmation_required", "Read and accept the retained-copy save notice.", 409)
        self.service.live()
        async with self.admission:
            context = self.context(actor, body["workspace_id"], body["instance_id"])
            signature = digest(body)
            try:
                previous = self.store.get(key)
            except Failure as exc:
                if exc.status != 404:
                    raise
                previous = None
            if previous:
                if previous["request_digest"] != signature:
                    raise Failure("idempotency_conflict", "This save key belongs to different text or files.", 409)
                return await self._status(actor, {**context, "operation_id": key})
            items = []
            for item in body["items"]:
                root = self.files.store.root(item["root_id"])
                self.check(actor, context, root, True)
                entry = self.files.refs.resolve(root, item["entry_id"])
                items.append({"id": secrets.token_hex(16), "root_id": root["id"], "root": root,
                              "entry_id": item["entry_id"], "reference": entry,
                              "expected_sha256": item["sha256"], "submitted_sha256": hashlib.sha256(item["text"].encode()).hexdigest(),
                              "state": "pending", "retained": False, "resolved": False, "receipt": {}})
            value = {**context, "id": key, "actor": actor, "key": key, "request_digest": signature,
                     "created_at": time.time(), "updated_at": time.time(), "state": "unknown", "items": items}
            self.store.insert(value)
            self.service.store.audit("module.editor.save", key, "accepted", actor)
            for item, source in zip(items, body["items"], strict=True):
                try:
                    self.check(actor, context, item["root"], True)
                    item.update(state="unknown", retained=True)
                    self.store.save(value)
                    result, _ = await self.call(actor, context, item["root"], "editor.save", write=True,
                        data=source["text"].encode(), operation_id=item["id"], entry=item["reference"], expected_sha256=source["sha256"])
                    self.apply(item, result)
                except Failure as exc:
                    if item["state"] == "pending" or exc.code in {
                        "stale_entry", "editor_conflict", "editor_metadata", "editor_capacity",
                        "editor_text", "editor_type", "editor_revision", "editor_changed", "capacity", "read_only",
                    }:
                        item.update(state="failed", retained=False)
                    item["error"] = self.error(exc)
                finally:
                    value["state"] = self.state(value)
                    self.store.save(value)
            self.service.store.audit("module.editor.save", key, value["state"], actor)
            self.record_context(actor, {**context, "operation_id": key})
            return self.public(value)

    @staticmethod
    def apply(item, result):
        if result.get("id") != item["id"] or result.get("state") not in {"preparing", "unknown", "succeeded", "failed", "conflict"}:
            raise Failure("editor_response", "The helper edit receipt is invalid.", 502)
        item.update(receipt=result, state="unknown" if result["state"] == "preparing" else result["state"],
                    retained=bool(result.get("retained")), resolved=bool(result.get("resolved")), message=result.get("message", ""), error=None)

    async def status(self, actor, body):
        async with self.admission:
            return await self._status(actor, body)

    async def _status(self, actor, body):
        value, context = self.record_context(actor, body)
        for item in value["items"]:
            if item["state"] == "pending":
                item.update(state="failed", message="The save stopped before dispatch.")
            elif item["state"] == "unknown":
                try:
                    result, _ = await self.call(actor, context, item["root"], "editor.status", operation_id=item["id"])
                    self.apply(item, result)
                except Failure as exc:
                    item["error"] = self.error(exc)
        value["state"] = self.state(value)
        self.store.save(value)
        return self.public(value)

    async def operations(self, actor, body):
        context = self.context(actor, body["workspace_id"], body["instance_id"])
        result = []
        for value in self.store.all():
            if any(value[key] != context[key] for key in ("workspace_id", "instance_id", "package_digest", "targets")):
                continue
            try:
                self.record_context(actor, {**body, "operation_id": value["id"]})
                result.append(self.public(value))
            except Failure:
                continue
        return {"operations": result}

    async def recovery(self, actor, body):
        value, context = self.record_context(actor, body)
        item = next((item for item in value["items"] if item["id"] == body["item_id"]), None)
        if item is None:
            raise Failure("editor_item", "The selected edit item was not found.", 404)
        result, data = await self.call(actor, context, item["root"], "editor.recovery", operation_id=item["id"], copy=body["copy"])
        if len(data) > 262144 or hashlib.sha256(data).hexdigest() != result.get("sha256"):
            raise Failure("editor_response", "The retained copy failed its content check.", 502)
        return {"text": data.decode("utf-8"), "sha256": result["sha256"]}

    async def cleanup(self, actor, body):
        self.service.live()
        async with self.admission:
            value, context = self.record_context(actor, body)
            requested = set(body["item_ids"])
            if requested - {item["id"] for item in value["items"]}:
                raise Failure("editor_item", "An edit item is not in this receipt.", 409)
            for item in value["items"]:
                if item["id"] not in requested:
                    continue
                result, _ = await self.call(actor, context, item["root"], "editor.cleanup", write=True,
                    operation_id=item["id"], confirm=body["confirm"], recovered=body.get("recovered", False))
                self.apply(item, result)
                self.store.save(value)
            self.service.store.audit("module.editor.cleanup", value["id"], "succeeded", actor)
            return self.public(value)

    async def remove(self, actor, body):
        self.service.live()
        async with self.admission:
            value, context = self.record_context(actor, body)
            for item in value["items"]:
                self.check(actor, context, item["root"], True)
            if any(item["retained"] or item["state"] in {"pending", "unknown"} for item in value["items"]):
                raise Failure("editor_retained", "Recover and remove all retained copies first.", 409)
            for item in value["items"]:
                result, _ = await self.call(actor, context, item["root"], "editor.forget", write=True, operation_id=item["id"])
                if result != {"id": item["id"], "removed": True}:
                    raise Failure("editor_response", "The helper receipt removal was not confirmed.", 502)
            self.store.remove(value["id"])
            self.service.store.audit("module.editor.receipt.remove", value["id"], actor=actor)
            return {"removed": True}
