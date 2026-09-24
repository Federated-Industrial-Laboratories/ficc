# SPDX-License-Identifier: Apache-2.0
"""Export, import or explicitly archive selected bus runs with stopped state ownership."""

import hashlib
import json
import os
import secrets
from datetime import datetime

from . import backup_io
from .agent_store import CAPS, CLOSED, SETTLED, AgentStore
from .bus_schema import envelope, portable
from .state_lock import StateLock
from .store import Store

MAX_EXPORT = 256 * 1024 * 1024


def write_file(folder, name, data):
    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=folder)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def export_run(store, run_id, output, archive=False):
    records = AgentStore(store)
    run = records.get("bus_runs", run_id)
    agents = [value for value in records.all("agents") if value["run_id"] == run_id]
    deliveries = [value for value in records.all("bus_deliveries") if value["run_id"] == run_id]
    messages = [value for value in records.all("bus_messages") if value["run_id"] == run_id]
    if archive and (run["state"] != "closed" or any(value["state"] not in CLOSED for value in agents)
                    or any(value["state"] not in SETTLED for value in deliveries)):
        raise ValueError("Archival requires a closed run with stopped agents and resolved deliveries.")
    members = {"messages.jsonl": b"".join(json.dumps(envelope(value), ensure_ascii=False, allow_nan=False).encode() + b"\n" for value in messages),
               "run.json": backup_io.encode(run), "agents.json": backup_io.encode(agents),
               "deliveries.json": backup_io.encode(deliveries)}
    manifest = {"format": 1, "run_id": run_id, "members": {name: {"size": len(data),
                "sha256": hashlib.sha256(data).hexdigest()} for name, data in members.items()}}
    if sum(len(data) for data in members.values()) > MAX_EXPORT:
        raise ValueError("The selected bus export exceeds capacity.")
    if output.exists() or output.is_symlink():
        with backup_io.directory(output) as folder:
            if set(os.listdir(folder)) - {"node-archives.json", ".node-archives.pending"} != {*members, "manifest.json"}:
                raise ValueError("The existing export member set differs.")
            if backup_io.read(folder, "manifest.json", 65536) != backup_io.encode(manifest):
                raise ValueError("The existing export does not match this run.")
            for name, data in members.items():
                if backup_io.read(folder, name, MAX_EXPORT) != data:
                    raise ValueError("The existing export content changed.")
    else:
        with backup_io.staging(output) as (folder, _):
            for name, data in members.items():
                write_file(folder, name, data)
            write_file(folder, "manifest.json", backup_io.encode(manifest))
    if archive:
        with store.lock, store.db:
            for table, values in (("agents", agents), ("bus_messages", messages), ("bus_deliveries", deliveries), ("bus_runs", [run])):
                store.db.executemany(f"DELETE FROM {table} WHERE id=?", [(value["id"],) for value in values])
        store.audit("bus.archive", run_id)
    return {"run_id": run_id, "messages": len(messages), "archived": archive, "output": str(output)}


def import_run(store, source):
    with backup_io.directory(source.parent, private=False) as folder:
        raw = backup_io.read(folder, source.name, MAX_EXPORT)
    lines = portable(raw.decode("utf-8").splitlines())
    records = AgentStore(store)
    digest = hashlib.sha256(raw).hexdigest()
    intent = {"sha256": digest}
    existing = records.retry("bus_runs", "local-import", digest, intent)
    if existing:
        return {"run_id": existing["id"], "messages": len(lines), "imported": False}
    if len(records.all("bus_messages")) + len(lines) > CAPS["bus_messages"]:
        raise ValueError("The imported messages exceed retained capacity.")
    run = records.new("bus_runs", "local-import", digest, intent, name=lines[0]["run"], state="closed")
    with store.lock:
        try:
            store.db.execute("BEGIN IMMEDIATE")
            records.save("bus_runs", run, commit=False)
            for ordinal, item in enumerate(lines, 1):
                message = records.new("bus_messages", "local-import-" + run["id"], secrets.token_hex(16), item,
                    run_id=run["id"], run_name=run["name"], sender_id=item["agent"], sequence=item["seq"],
                    ordinal=ordinal, type=item["type"], body=item["body"], reply_to=None, recipient_ids=[])
                if "ts" in item:
                    stamp = datetime.fromisoformat(item["ts"])
                    if stamp.tzinfo is None:
                        raise ValueError("Imported timestamps require an explicit timezone.")
                    message["created_at"] = stamp.timestamp()
                records.save("bus_messages", message, commit=False)
            store.db.commit()
        except BaseException:
            store.db.rollback()
            raise
    return {"run_id": run["id"], "messages": len(lines), "imported": True}


def execute(args):
    with StateLock(args.state_dir):
        store = Store(args.state_dir / "state.sqlite3")
        try:
            if args.command == "bus-import":
                result = import_run(store, args.input.absolute())
            else:
                if args.command == "bus-archive" and not args.confirm:
                    raise ValueError("Use --confirm to archive the selected closed run after durable export.")
                result = export_run(store, args.run, args.output.absolute(), args.command == "bus-archive")
            print(json.dumps(result, indent=2))
        finally:
            store.close()
