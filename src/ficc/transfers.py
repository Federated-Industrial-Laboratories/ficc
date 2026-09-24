# SPDX-License-Identifier: Apache-2.0
"""Admit scoped transfers and retain resumable per-file progress."""

import asyncio
import copy
import secrets
import time
from contextlib import suppress

from ficc_node.file_access import MAX_FILE, FileError, new_name
from ficc_node.job_state import digest

from . import transfer_work
from .errors import Failure
from .file_store import FileStore, key_check
from .settings import private_directory


class Transfers:
    def __init__(self, service):
        self.service, self.files = service, service.files
        self.store = FileStore(service.store, "transfers")
        self.previews: dict[str, dict] = {}
        self.admission = asyncio.Lock()
        self.tasks: dict[str, asyncio.Task] = {}
        self.locks: dict[str, asyncio.Lock] = {}
        self.workers = asyncio.Semaphore(4)
        private_directory(service.settings.state_dir / "downloads")

    def check(self, actor, item, kind):
        if item.get("source"):
            self.files.check(actor, "files:read", item["source"]["root"])
        if kind != "download":
            self.files.check(actor, "files:write", item["destination"]["root"])

    async def destination(self, operation, item, action, data=b"", timeout=15, **values):
        result, binary = await self.files.transport.call(item["destination"]["root"],
            {"action": action, "transfer_id": item["id"], **values}, data=data,
            check=lambda: self.check(operation["actor"], item, operation["kind"]), timeout=timeout)
        if binary:
            raise Failure("invalid_file_response", "The destination returned unexpected file bytes.", 502)
        return result

    async def source(self, operation, item, action, timeout=15, **values):
        return await self.files.transport.call(item["source"]["root"],
            {"action": action, "entry": item["source"]["reference"], **values},
            check=lambda: self.check(operation["actor"], item, operation["kind"]), timeout=timeout)

    async def preview(self, body, actor):
        self.service.live()
        kind, sources = body["kind"], body["sources"]
        if not 1 <= len(sources) <= 64:
            raise Failure("invalid_sources", "Select from one to 64 files.")
        if kind == "download":
            path = self.service.settings.state_dir / "downloads"
            root = {"id": self.service.store.get_setting("controller_id", None), "path": str(path),
                    "node_id": None, "label": "Download spool", "read_only": False, "revision": "1", "export": True}
            result, _ = await self.files.transport.call(root, {"action": "file.root"})
            root["identity"] = result["identity"]
            destination = {"root": root, "reference": result["reference"]}
        else:
            dest = body.get("destination") or {}
            root, ref = self.files.resolve(dest.get("root_id"), dest.get("entry_id"), actor, "files:write")
            result = await self.files.stat(root, ref, actor, "files:write")
            if result["kind"] != "directory":
                raise Failure("invalid_destination", "Select a destination directory.")
            destination = {"root": root, "reference": ref}
        items, conflicts, seen = [], [], set()
        for source in sources:
            item_id = secrets.token_hex(16)
            if kind == "upload":
                name, size = source.get("name"), source.get("size")
                try:
                    raw_name = new_name(name)
                except (FileError, UnicodeError) as exc:
                    raise Failure("invalid_name", "Enter a valid upload name.") from exc
                if type(size) is not int or not 0 <= size <= MAX_FILE:
                    raise Failure("file_limit", "Each file must be no larger than 16 GiB.")
                saved_source, name_b64 = None, None
            else:
                root, ref = self.files.resolve(source.get("root_id"), source.get("entry_id"), actor)
                info = await self.files.stat(root, ref, actor)
                if info["kind"] != "file" or info["size"] > MAX_FILE:
                    raise Failure("unsupported_file", "Select regular files no larger than 16 GiB.")
                saved_source = {"root": root, "reference": ref}
                name, size, name_b64 = info["name"], info["size"], ref["parts"][-1]
                raw_name = name_b64.encode()
            if raw_name in seen:
                raise Failure("duplicate_name", "Selected files must have distinct destination names.", 409)
            seen.add(raw_name)
            spec = {"parent": destination["reference"], "name": item_id if kind == "download" else name,
                    "name_b64": None if kind == "download" else name_b64, "size": size, "expected": None}
            item = {"id": item_id, "name": name, "size": size, "offset": 0, "source": saved_source,
                    "destination": copy.deepcopy(destination), "spec": spec, "state": "queued", "sha256": None, "error": None,
                    "cleanup_pending": False, "actor": actor}
            self.check(actor, item, kind)
            existing, _ = await self.files.transport.call(destination["root"],
                {"action": "file.destination", "parent": destination["reference"], **{key: spec[key] for key in ("name", "name_b64")}},
                check=lambda: self.check(actor, item, kind))
            spec["expected"] = existing["identity"]
            if existing["identity"]:
                conflicts.append({"name": name, "exists": True})
                if existing.get("kind") != "file":
                    raise Failure("destination_conflict", "The destination is not a regular file.", 409)
            items.append(item)
        self.previews = {key: value for key, value in self.previews.items() if value["expires_at"] > time.time()}
        if len(self.previews) >= 64:
            raise Failure("capacity", "The transfer preview limit was reached.", 429)
        value = {"preview_id": secrets.token_hex(16), "expires_at": time.time()+120, "actor": actor,
                 "kind": kind, "items": items, "conflicts": conflicts, "overwrite": body.get("overwrite", False),
                 "request_digest": digest(body), "request": copy.deepcopy(body)}
        self.previews[value["preview_id"]] = value
        return {"preview_id": value["preview_id"], "expires_at": value["expires_at"], "request_digest": value["request_digest"],
                "kind": kind, "items": [{"id": item["id"], "name": item["name"], "size": item["size"]} for item in items],
                "total_bytes": sum(item["size"] for item in items), "conflicts": conflicts,
                "relay": kind == "copy" and any(item["source"]["root"].get("node_id") and destination["root"].get("node_id") for item in items)}

    async def submit(self, preview_id, key, actor):
        self.service.live()
        key_check(key)
        async with self.admission:
            old = self.store.existing(actor, key)
            if old:
                if old["preview_id"] != preview_id:
                    raise Failure("idempotency_conflict", "This key belongs to another transfer.", 409)
                for item in old["items"]:
                    self.check(actor, item, old["kind"])
                return old
            preview = self.previews.get(preview_id)
            if not preview or preview["actor"] != actor or preview["expires_at"] <= time.time():
                raise Failure("preview_expired", "Create a new transfer preview.", 409)
            if preview["conflicts"] and not preview["overwrite"]:
                raise Failure("overwrite_required", "Confirm replacement of the listed destination files.", 409)
            active = [item for op in self.store.iterate() for item in op["items"] if item["state"] not in {"succeeded", "cancelled"}
                      or item.get("cleanup_pending") or (op["kind"] == "download" and item["state"] == "succeeded")]
            if len(active)+len(preview["items"]) > 64 or sum(item["size"] for item in active+preview["items"]) > 64*1024**3:
                raise Failure("capacity", "The retained transfer quota is full.", 409)
            for item in preview["items"]:
                self.check(actor, item, preview["kind"])
            value = {**copy.deepcopy(preview), "id": secrets.token_hex(16), "key": key,
                     "created_at": time.time(), "updated_at": time.time(), "state": "queued", "created_by": actor,
                     "policy_revision": 1}
            self.store.insert(value)
            self.service.store.audit("transfer." + value["kind"], value["id"], "queued", actor)
            if value["kind"] != "upload":
                for item in value["items"]:
                    self.start(value["id"], item["id"])
            return value

    def start(self, operation_id, item_id):
        if item_id in self.tasks:
            return
        async def work():
            async with self.workers:
                await transfer_work.run(self, operation_id, item_id)
        task = asyncio.create_task(work())
        self.tasks[item_id] = task
        task.add_done_callback(lambda _: self.tasks.pop(item_id, None))

    def save_item(self, operation, item):
        current = self.store.get(operation["id"])
        current["items"] = [copy.deepcopy(item) if value["id"] == item["id"] else value for value in current["items"]]
        states = {value["state"] for value in current["items"]}
        current["state"] = "succeeded" if states == {"succeeded"} else "cancelled" if states == {"cancelled"} else (
            "unknown" if "unknown" in states else "running" if states & {"running", "queued", "committing"} else "interrupted")
        self.store.save(current)

    def selected(self, operation_id, item_id, actor):
        operation = self.store.get(operation_id)
        item = next((value for value in operation["items"] if value["id"] == item_id), None)
        if item is None:
            raise Failure("not_found", "The transfer item was not found.", 404)
        self.check(actor, item, operation["kind"])
        return operation, item

    async def upload(self, operation_id, item_id, actor, offset, data, sha256):
        operation, item = self.selected(operation_id, item_id, actor)
        if operation["kind"] != "upload":
            raise Failure("invalid_action", "This transfer is not a browser upload.")
        async with self.locks.setdefault(item_id, asyncio.Lock()):
            operation, item = self.selected(operation_id, item_id, actor)
            if item["state"] not in {"queued", "running"}:
                raise Failure("transfer_state", "Resume this upload before sending more bytes.", 409)
            operation["actor"] = actor
            replay_offset, replay_until = item.get("replay_offset", 0), item.get("replay_until", 0)
            if replay_offset < replay_until and offset > replay_offset:
                raise Failure("source_verification_required", "Verify the accepted source prefix before sending new bytes.", 409)
            await self.destination(operation, item, "transfer.begin", spec=item["spec"])
            result = await self.destination(operation, item, "transfer.write", data=data, offset=offset, sha256=sha256)
            item.update(offset=result["offset"], state="running", error=None)
            if replay_offset < replay_until and offset == replay_offset:
                item["replay_offset"] = replay_offset + len(data)
            self.save_item(operation, item)
            return {"offset": item["offset"], "sha256": sha256, "state": item["state"]}

    async def finish(self, operation_id, item_id, actor):
        async with self.locks.setdefault(item_id, asyncio.Lock()):
            operation, item = self.selected(operation_id, item_id, actor)
            if operation["kind"] != "upload":
                raise Failure("invalid_action", "This transfer is not a browser upload.")
            if item["state"] == "succeeded":
                return self.view(operation, actor, mutation_ids=[item_id])
            if item.get("replay_offset", 0) < item.get("replay_until", 0):
                raise Failure("source_verification_required", "Verify the accepted source prefix before finishing.", 409)
            operation["actor"] = actor
            await self.destination(operation, item, "transfer.begin", spec=item["spec"])
            result = await self.destination(operation, item, "transfer.verify", timeout=300)
            if result["offset"] != item["size"]:
                raise Failure("incomplete_transfer", "Upload every file chunk before finishing.", 409)
            item.update(sha256=result["prefix_sha256"], offset=result["offset"])
            await transfer_work.finish(self, operation, item)
            return self.view(self.store.get(operation_id), actor, mutation_ids=[item_id])

    async def change(self, operation_id, item_ids, actor, resume=False, discard=False):
        if len(set(item_ids)) != len(item_ids):
            raise Failure("invalid_items", "Select distinct transfer items.")
        for item_id in item_ids:
            self.selected(operation_id, item_id, actor)
        self.service.store.audit("transfer.resume" if resume else "transfer.cancel", operation_id, "requested", actor)
        for item_id in item_ids:
            task = self.tasks.get(item_id)
            if task:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            async with self.locks.setdefault(item_id, asyncio.Lock()):
                operation, item = self.selected(operation_id, item_id, actor)
                operation["actor"] = actor
                if item["state"] == "succeeded" and (operation["kind"] == "download" or item.get("cleanup_pending")) and discard and not resume:
                    result = await self.destination(operation, item, "transfer.cancel", discard_partial=True)
                    item["state"] = result["state"]
                    item["cleanup_pending"] = result.get("cleanup_pending", False)
                    self.save_item(operation, item)
                    continue
                if item["state"] in {"succeeded", "cancelled"}:
                    continue
                if item["state"] in {"unknown", "committing"}:
                    if not resume:
                        raise Failure("outcome_unknown", "Reconcile the uncertain commit before cleanup.", 409)
                    status = await self.destination(operation, item, "transfer.status")
                    if status["state"] == "committing":
                        status = await self.destination(operation, item, "transfer.commit", sha256=item["sha256"], timeout=300)
                    if status["state"] == "succeeded":
                        item.update(state="succeeded", offset=status["offset"], sha256=status["sha256"], error=None,
                                    cleanup_pending=status.get("cleanup_pending", False))
                        self.save_item(operation, item)
                        continue
                    if status["state"] != "running":
                        raise Failure("outcome_unknown", "The destination still requires manual recovery.", 409)
                await self.destination(operation, item, "transfer.begin", spec=item["spec"], prepare=resume)
                result = await self.destination(operation, item, "transfer.resume" if resume else "transfer.cancel",
                                                **({} if resume else {"discard_partial": discard}), timeout=300)
                item.update(state="running" if resume else result["state"], offset=result["offset"], error=None)
                item["actor"] = actor
                if resume and operation["kind"] == "upload":
                    item.update(replay_offset=0, replay_until=result["offset"])
                self.save_item(operation, item)
                if resume and operation["kind"] != "upload":
                    self.start(operation_id, item_id)
        return self.view(self.store.get(operation_id), actor, mutation_ids=item_ids)

    def view(self, operation, actor, mutation_ids=None):
        visible = []
        for item in operation["items"]:
            if mutation_ids is not None and item["id"] not in mutation_ids:
                continue
            try:
                if mutation_ids is not None:
                    self.check(actor, item, operation["kind"])
                else:
                    if item.get("source"):
                        self.files.check(actor, "files:read", item["source"]["root"])
                    if operation["kind"] != "download":
                        self.files.check(actor, "files:read", item["destination"]["root"])
            except Failure:
                continue
            visible.append({**{key: item[key] for key in ("id", "name", "size", "offset", "state", "sha256", "error")},
                            "cleanup_pending": item.get("cleanup_pending", False),
                            "resumable": item["state"] == "interrupted" or (
                                operation["kind"] == "upload" and item["state"] in {"queued", "running"})})
        if not visible:
            raise Failure("not_found", "The transfer was not found.", 404)
        return {**{key: operation[key] for key in ("id", "kind", "state", "created_at", "updated_at")}, "items": visible}

    def active(self, node_id=None, root_id=None):
        return any((item["state"] not in {"succeeded", "cancelled"} or item.get("cleanup_pending") or
                    (operation["kind"] == "download" and item["state"] == "succeeded")) and any(
            (node_id is None or endpoint["root"].get("node_id") == node_id) and
            (root_id is None or endpoint["root"]["id"] == root_id) for endpoint in [item["destination"], item.get("source")] if endpoint)
            for operation in self.store.iterate() for item in operation["items"])

    async def poll(self):
        for operation in self.store.iterate():
            for item in operation["items"]:
                if item["state"] in {"running", "queued", "committing"} and item["id"] not in self.tasks:
                    item["state"] = "unknown" if item["state"] == "committing" else "interrupted"
                    self.save_item(operation, item)
        await asyncio.Event().wait()

    async def close(self):
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
