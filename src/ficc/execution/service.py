# SPDX-License-Identifier: Apache-2.0
"""Serve local executor operations with socket credentials and an independent lease monitor."""

import asyncio
import contextlib
import os
import re
import signal
import stat
from pathlib import Path

from .client import credentials, receive, send
from .files import directory
from .ledger import Conflict
from .monitor import Monitor, notify
from .protocol import (
    MAX_MESSAGE,
    Admission,
    BoundRequest,
    Collect,
    InputStatus,
    InputWrite,
    Prepare,
    ReconcileAbsent,
    RejectAbsent,
    Renew,
    SetOffer,
    Snapshot,
    authorize,
    decode,
)
from .spec import Plan, encoded
from .supervisor import fence, public
from .wire import MAX_REPLY, REPLY


def error(exc):
    text = str(exc)
    code = text if isinstance(exc, Conflict) and re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", text) else "executor_refused"
    return {"code": code, "message": "Local execution refused this operation. Refresh its state and inspect the local service."}


def dispatch(supervisor, request, uid):
    authorize(request, uid, supervisor.settings)
    header = {"version": 1, "id": request.id, "deployment_id": supervisor.settings.deployment_id,
              "node_id": supervisor.settings.node_id, "ok": True}
    if isinstance(request, Snapshot):
        return {**header, "snapshot": supervisor.snapshot(request.after)}
    if isinstance(request, SetOffer):
        return {**header, "offer": supervisor.set_offer(request)}
    if isinstance(request, BoundRequest):
        supervisor.bind(request)
    items = (request.attempts if isinstance(request, Prepare) else request.leases if isinstance(request, Renew)
             else request.objects if isinstance(request, InputStatus) else request.writes if isinstance(request, InputWrite)
             else request.reads if isinstance(request, Collect) else request.plans
             if isinstance(request, RejectAbsent | ReconcileAbsent) else request.attempts)
    results = []
    for item in items:
        plan = item.plan if isinstance(item, Admission) else item if isinstance(item, Plan) else None
        asked = {"attempt_id": plan.attempt_id, "generation": plan.generation,
                 "plan_digest": plan.digest()} if plan is not None else item.model_dump(
                     include={"attempt_id", "generation", "plan_digest"})
        try:
            if request.action == "prepare":
                value = supervisor.prepare(item)
            elif request.action in {"reject_absent", "reconcile_absent"}:
                value = supervisor.reject_absent(item, legacy=request.action == "reconcile_absent")
            elif request.action == "renew":
                value = supervisor.renew(item)
            elif request.action == "start":
                value = supervisor.start(item)
            elif request.action == "observe":
                value = supervisor.ledger.fenced(asked["attempt_id"], asked["generation"], asked["plan_digest"])
            elif request.action == "stop":
                value = supervisor.request_stop(item)
            elif request.action == "release":
                value = supervisor.release(item)
            elif request.action in {"input_status", "input_write"}:
                operation = supervisor.input_status if request.action == "input_status" else supervisor.input_write
                results.append({**asked, "ok": True, **operation(item)})
                continue
            else:
                results.append({**asked, "ok": True, **supervisor.collect(item)})
                continue
            results.append({**asked, "ok": True, "attempt": public(value)})
        except Exception as exc:
            results.append({**asked, "ok": False, "error": error(exc)})
    return {**header, "results": results}


class Service:
    def __init__(self, supervisor):
        self.supervisor, self.monitor = supervisor, Monitor(supervisor)
        self.connections = 0
        self.servers, self.paths = [], []
        self.stop = asyncio.Event()

    async def accept(self, reader, writer):
        if self.connections >= 16:
            writer.close()
            await writer.wait_closed()
            return
        self.connections += 1
        try:
            uid = credentials(writer.get_extra_info("socket"))[1]
            allowed = {0, self.supervisor.settings.transport_uid, *self.supervisor.settings.local_owner_uids}
            if uid not in allowed:
                return
            async with asyncio.timeout(3):
                request = decode(await receive(reader, MAX_MESSAGE))
            try:
                result = await asyncio.to_thread(dispatch, self.supervisor, request, uid)
            except Exception as exc:
                result = {"version": 1, "id": request.id, "deployment_id": self.supervisor.settings.deployment_id,
                          "node_id": self.supervisor.settings.node_id, "ok": False, "error": error(exc)}
            reply = REPLY.validate_python(result)
            async with asyncio.timeout(3):
                await send(writer, encoded(reply.model_dump()), MAX_REPLY)
        except (ValueError, OSError, TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            self.connections -= 1
            writer.close()
            await writer.wait_closed()

    async def watch(self):
        while not self.stop.is_set():
            await asyncio.to_thread(self.monitor.tick)
            notify("WATCHDOG=1")
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=0.2)
            except TimeoutError:
                pass

    async def open(self):
        root = Path(self.supervisor.settings.sockets)
        directory(root)
        identities = {"admin.sock": 0, "transport.sock": self.supervisor.settings.transport_uid}
        identities.update({f"owner-{uid}.sock": uid for uid in self.supervisor.settings.local_owner_uids})
        for name, uid in identities.items():
            path = root / name
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != uid:
                    raise ValueError("An executor socket path has another identity.")
                path.unlink()
            server = await asyncio.start_unix_server(self.accept, path=path, limit=MAX_MESSAGE + 4)
            os.chown(path, uid, 0)
            path.chmod(0o600)
            self.servers.append(server)
            self.paths.append((path, path.lstat().st_ino))

    async def serve(self):
        self.supervisor.envelope.supervisor(self.supervisor.settings)
        await asyncio.to_thread(self.monitor.recover)
        await self.open()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, self.stop.set)
        notify("READY=1\nWATCHDOG=1")
        monitor = asyncio.create_task(self.watch())
        halted = asyncio.create_task(self.stop.wait())
        try:
            done, _pending = await asyncio.wait((monitor, halted), return_when=asyncio.FIRST_COMPLETED)
            if monitor in done:
                await monitor
        finally:
            self.stop.set()
            for server in self.servers:
                server.close()
                await server.wait_closed()
            for value in self.supervisor.ledger.retained():
                await asyncio.to_thread(self.supervisor.request_stop, fence(value))
            with contextlib.suppress(Exception):
                await monitor
            halted.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await halted
            await asyncio.to_thread(self.supervisor.close)
            for path, inode in self.paths:
                if path.exists() and path.lstat().st_ino == inode:
                    path.unlink()
