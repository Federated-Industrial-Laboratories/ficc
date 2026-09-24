# SPDX-License-Identifier: Apache-2.0
"""Checkpoint quiescent node archives before retiring canonical host records."""

import asyncio
import json
import os
from contextlib import AsyncExitStack
from pathlib import Path

from . import backup_io
from .agent_store import CLOSED, SETTLED
from .bus_cli import export_run, write_file
from .errors import Failure

RECEIPTS = "node-archives.json"
SCRATCH = ".node-archives.pending"


def receipts(folder):
    if SCRATCH in os.listdir(folder):
        backup_io.read(folder, SCRATCH, 1024 * 1024)
        os.unlink(SCRATCH, dir_fd=folder)
        os.fsync(folder)
    if RECEIPTS not in os.listdir(folder):
        return []
    value = json.loads(backup_io.read(folder, RECEIPTS, 1024 * 1024))
    if not isinstance(value, list) or len(value) > 512:
        raise ValueError("The node archive receipt set is invalid.")
    return value


def save_receipts(folder, rows):
    raw = backup_io.encode(rows)
    if len(raw) > 1024 * 1024:
        raise ValueError("The node archive receipts exceed capacity.")
    write_file(folder, SCRATCH, raw)
    os.replace(SCRATCH, RECEIPTS, src_dir_fd=folder, dst_dir_fd=folder)
    os.fsync(folder)


async def archive(service, run_id, output):
    service.live()
    destination = Path(output).absolute()
    async with service.agents.lock, service.terminals.lock, AsyncExitStack() as locks:
        try:
            run = service.bus.store.get("bus_runs", run_id)
        except Failure as exc:
            if exc.status != 404:
                raise
            return completed(service, run_id, destination)
        agents = service.bus.agents(run_id)
        for agent in agents:
            await locks.enter_async_context(service.agents.agent_locks.setdefault(agent["id"], asyncio.Lock()))
        deliveries = service.bus.deliveries(run_id)
        if run["state"] != "closed" or any(value["state"] not in CLOSED or value.get("outbox_acks") for value in agents) or any(value["state"] not in SETTLED for value in deliveries):
            raise Failure("run_busy", "A closed run with stopped agents and resolved deliveries is required.", 409)
        export_run(service.store, run_id, destination)
        with backup_io.directory(destination) as folder:
            saved = receipts(folder)
            allowed = {agent["id"]: agent["node_id"] for agent in agents}
            seen = set()
            for row in saved:
                if row.get("agent_id") not in allowed or row.get("node_id") != allowed[row["agent_id"]] or row.get("state") != "archived" or row["agent_id"] in seen:
                    raise ValueError("A saved node archive receipt has a conflicting identity.")
                seen.add(row["agent_id"])
            selected = [agent for agent in agents if agent["id"] not in seen][:8]
            slots = asyncio.Semaphore(4)
            async def one(agent):
                async with slots:
                    if service.store.node(agent["node_id"])["fingerprint"] != agent["fingerprint"]:
                        raise Failure("identity_changed", "The archived agent node identity changed.", 409)
                    result = await service.agents.remote(agent["node_id"], "archive", {
                        "controller_id": service.agents.controller, "agent_id": agent["id"]})
                    if result.get("state") != "archived" or result.get("agent_id") != agent["id"]:
                        raise Failure("invalid_archive_response", "The node did not confirm the exact agent archive.", 502)
                    saved.append({"node_id": agent["node_id"], **result})
                    save_receipts(folder, saved)
            outcomes = await asyncio.gather(*(one(agent) for agent in selected), return_exceptions=True)
            for result in outcomes:
                if isinstance(result, BaseException):
                    raise result
            if len(saved) < len(agents):
                return {"run_id": run_id, "archived": False, "remaining": len(agents) - len(saved), "output": str(destination)}
        with service.store.lock, service.store.db:
            for table, rows in (("agents", agents), ("bus_deliveries", deliveries),
                                ("bus_messages", service.bus.messages(run_id)), ("bus_runs", [run])):
                service.store.db.executemany(f"DELETE FROM {table} WHERE id=?", [(row["id"],) for row in rows])
        service.store.audit("bus.archive", run_id)
        return {"run_id": run_id, "archived": True, "output": str(destination), "nodes": saved}


def completed(service, run_id, destination):
    import hashlib
    with backup_io.directory(destination) as folder:
        manifest = json.loads(backup_io.read(folder, "manifest.json", 65536))
        if manifest.get("format") != 1 or manifest.get("run_id") != run_id or set(manifest.get("members", {})) != {"messages.jsonl", "run.json", "agents.json", "deliveries.json"}:
            raise ValueError("The completed archive manifest does not match the selected run.")
        for name, expected in manifest["members"].items():
            raw = backup_io.read(folder, name, 256 * 1024 * 1024)
            if expected != {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}:
                raise ValueError("A completed archive member changed.")
        run = json.loads(backup_io.read(folder, "run.json", 32768))
        agents = json.loads(backup_io.read(folder, "agents.json", 8 * 1024 * 1024))
        saved = receipts(folder)
        if run.get("id") != run_id or run.get("state") != "closed" or {row["agent_id"] for row in saved} != {row["id"] for row in agents}:
            raise ValueError("The completed archive lacks exact closed-run node receipts.")
    if service.bus.agents(run_id) or service.bus.messages(run_id) or service.bus.deliveries(run_id):
        raise ValueError("The completed archive has conflicting retained controller records.")
    return {"run_id": run_id, "archived": True, "output": str(destination), "nodes": saved}
