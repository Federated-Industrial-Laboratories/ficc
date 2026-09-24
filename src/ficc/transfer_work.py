# SPDX-License-Identifier: Apache-2.0
"""Relay bounded file chunks and reconcile a verified destination commit."""

import asyncio
import hashlib

from ficc_node.file_access import CHUNK

from .errors import Failure


async def run(manager, operation_id, item_id):
    lock = manager.locks.setdefault(item_id, asyncio.Lock())
    async with lock:
        operation = manager.store.get(operation_id)
        item = next(value for value in operation["items"] if value["id"] == item_id)
        operation["actor"] = item.get("actor", operation["actor"])
        try:
            manager.check(operation["actor"], item, operation["kind"])
            item.update(state="running", error=None)
            manager.save_item(operation, item)
            destination = await manager.destination(operation, item, "transfer.begin", spec=item["spec"])
            if destination["state"] == "succeeded":
                item.update(state="succeeded", offset=destination["offset"], sha256=destination["sha256"],
                            cleanup_pending=destination.get("cleanup_pending", False))
                manager.save_item(operation, item)
                return
            result, _ = await manager.source(operation, item, "file.hash", timeout=300)
            if item.get("sha256") and item["sha256"] != result["sha256"]:
                raise Failure("source_changed", "The source changed since this transfer started.", 409)
            item["sha256"] = result["sha256"]
            destination = await manager.destination(operation, item, "transfer.resume")
            offset = destination["offset"]
            prefix = hashlib.sha256()
            for position in range(0, offset, CHUNK):
                _, data = await manager.source(operation, item, "file.read", offset=position,
                                                limit=min(CHUNK, offset-position))
                prefix.update(data)
            if prefix.hexdigest() != destination["prefix_sha256"]:
                raise Failure("source_changed", "The source no longer matches the retained partial file.", 409)
            item["offset"] = offset
            manager.save_item(operation, item)
            while item["offset"] < item["size"]:
                manager.check(operation["actor"], item, operation["kind"])
                offset = item["offset"]
                header, data = await manager.source(operation, item, "file.read", offset=offset, limit=CHUNK)
                if (not data or header.get("offset") != offset or header.get("next_offset") != offset + len(data)
                        or hashlib.sha256(data).hexdigest() != header.get("sha256")):
                    raise Failure("invalid_file_response", "The source chunk failed verification.", 502)
                destination = await manager.destination(operation, item, "transfer.write", data=data,
                                                          offset=offset, sha256=header["sha256"])
                if destination["offset"] != offset + len(data):
                    raise Failure("invalid_file_response", "The destination offset is invalid.", 502)
                item["offset"] = destination["offset"]
                manager.save_item(operation, item)
            result, _ = await manager.source(operation, item, "file.hash", timeout=300)
            if result["sha256"] != item["sha256"]:
                raise Failure("source_changed", "The source changed during transfer.", 409)
            await finish(manager, operation, item)
        except asyncio.CancelledError:
            item.update(state="unknown" if item["state"] == "committing" else "interrupted",
                        error={"code": "interrupted", "message": "The transfer was interrupted."})
            manager.save_item(operation, item)
            raise
        except Failure as exc:
            item.update(state="unknown" if item["state"] == "committing" else "interrupted",
                        error={"code": exc.code, "message": exc.message})
            manager.save_item(operation, item)


async def finish(manager, operation, item):
    manager.check(operation["actor"], item, operation["kind"])
    item["state"] = "committing"
    manager.save_item(operation, item)
    result = await manager.destination(operation, item, "transfer.commit", sha256=item["sha256"], timeout=300)
    if result["state"] != "succeeded" or result["sha256"] != item["sha256"] or result["offset"] != item["size"]:
        raise Failure("invalid_file_response", "The committed file could not be verified.", 502)
    item.update(state="succeeded", offset=item["size"], error=None, cleanup_pending=result.get("cleanup_pending", False))
    manager.save_item(operation, item)
