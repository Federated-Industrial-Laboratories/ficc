# SPDX-License-Identifier: Apache-2.0
"""Deliver bounded audit batches and own admission waits independently of node maintenance."""

import asyncio
import copy
import secrets
import time
from collections import deque

from . import audit_state, secret_io
from .audit_sdk import DELIVERY_SECONDS, AuditError, acknowledgement, batch, encoded, identity, load
from .errors import Failure
from .secrets import Secrets

ACTIONS = {"workload.submit", "workload.retry", "source.write", "source.object.begin", "source.object.part", "source.object.complete"}
ADMISSION_SECONDS = 12


class Delivery:
    def __init__(self, service):
        self.service = service
        self.required = bool(service.store.get_setting(audit_state.REQUIRED, False))
        self.config = self.state = self.driver = None
        self.task = None
        self.closed = False
        self.requests: deque[tuple[dict, asyncio.Future]] = deque()
        self.active = None
        self.wake = asyncio.Event()
        self.error = None
        self.dirty = False
        self.lag = 0
        try:
            with secret_io.directory(service.settings.state_dir / audit_state.PRIVATE) as folder:
                self.config = audit_state.configuration(secret_io.read(folder, audit_state.CONFIG, 32768))
            self.required = self.required or self.config["required"]
            self.state = audit_state.State(service.settings.state_dir, self.config)
            self.lag = self.state.value["last_seen"] - self.state.value["cursor"]
            self.driver = load(self.config["provider"]).configure(self.config["configuration"])
            if not callable(self.driver.append):
                raise AuditError("audit_provider")
        except FileNotFoundError:
            if self.required or self.config is not None:
                self.error = "audit_configuration"
        except Exception as exc:
            self.error = exc.code if isinstance(exc, AuditError) else "audit_configuration"
            # An unreadable configuration must never silently turn enforcement off.
            if self.config is None:
                self.required = True

    def status(self):
        saved = self.state.value if self.state is not None else {}
        return {"state": "unavailable" if self.error else "not_configured" if self.config is None else
                "backpressure" if self.lag > self.config["max_lag_events"] else "delivering" if saved.get("pending") or self.lag or saved.get("last_ack_at") is None else "current",
            "required": self.required, "error": self.error, "acknowledged_sequence": saved.get("sequence", 0),
            "delivered_through": saved.get("cursor", 0), "last_ack_at": saved.get("last_ack_at"),
            "pending_events": self.lag, "retention_gap_events": saved.get("gap_events", 0),
            "admission_waiters": len(self.requests) + int(self.active is not None),
            "pending_batch": saved.get("pending") is not None}

    def start(self):
        if self.task is None and self.config is not None and self.state is not None and self.driver is not None and not self.closed:
            self.task = asyncio.create_task(self.poll())

    async def io(self, function, *args):
        task = asyncio.create_task(asyncio.to_thread(function, *args))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Cancellation owns the single outstanding filesystem/database read.
            await task
            raise

    async def require(self, action, target, actor):
        if not self.required:
            return
        if action not in ACTIONS:
            raise ValueError("Unsupported protected audit action.")
        if self.closed or self.state is None or self.driver is None:
            raise Failure("audit_unavailable", str(AuditError()), 503)
        assert self.config is not None
        if self.lag > self.config["max_lag_events"] or len(self.requests) + int(self.active is not None) >= 16:
            raise Failure("audit_backpressure", str(AuditError("audit_backpressure")), 503)
        event = {"kind": "intent", "id": secrets.token_hex(16), "at": time.time(), "action": action,
            "target_sha256": identity(target), "actor_sha256": identity(actor.id),
            "subject_sha256": identity(actor.subject_id), "project_sha256": identity(actor.project_id)}
        future = asyncio.get_running_loop().create_future()
        self.requests.append((event, future))
        self.start()
        self.wake.set()
        try:
            await asyncio.wait_for(asyncio.shield(future), ADMISSION_SECONDS)
        except TimeoutError:
            raise Failure("audit_unavailable", str(AuditError()), 503) from None
        finally:
            if not future.done():
                future.cancel()

    def refuse(self, code):
        if self.active is not None:
            self.requests.appendleft(self.active)
            self.active = None
        while self.requests:
            _event, future = self.requests.popleft()
            if not future.done():
                future.set_exception(Failure(code, str(AuditError(code)), 503))

    async def persist(self):
        assert self.state is not None
        self.dirty = True
        await self.io(self.state.save, copy.deepcopy(self.state.value))
        self.dirty = False

    async def send(self):
        assert self.state is not None and self.config is not None and self.driver is not None
        value = self.state.value
        raw = encoded(value["pending"])
        credential = await self.io(Secrets(self.service.settings.state_dir).resolve, self.config["secret_reference"])
        async with asyncio.timeout(DELIVERY_SECONDS):
            result = await self.driver.append(raw, credential.value)
        acknowledgement(result, raw)
        sent = value["pending"]
        value.update(sequence=sent["sequence"], cursor=sent["through"], last_ack_at=time.time(), pending=None)
        value["gap_events"] += sum(event["last_id"] - event["first_id"] + 1
                                   for event in sent["events"] if event["kind"] == "retention_gap")
        await self.persist()
        self.lag = value["last_seen"] - value["cursor"]
        if self.active is not None:
            _event, future = self.active
            self.active = None
            if not future.done():
                future.set_result(None)

    async def step(self):
        assert self.state is not None
        if self.dirty:
            await self.persist()
            # An acknowledged intent is not released if checkpoint persistence failed.
            self.refuse("audit_unavailable")
        value = self.state.value
        if value["pending"] is not None:
            await self.send()
            return True
        last, through, events = await self.io(audit_state.page, self.service.store, value["cursor"])
        if last < value["last_seen"] or last < value["cursor"]:
            raise AuditError("audit_history")
        value["last_seen"] = last
        self.lag = last - value["cursor"]
        if not events:
            while self.requests:
                event, future = self.requests.popleft()
                if not future.done():
                    self.active = (event, future)
                    events = [event]
                    break
        if not events:
            if value["sequence"] == 0:
                events = [{"kind": "stream", "at": time.time()}]
        if not events:
            return False
        value["pending"] = {"version": 1, "stream_id": value["stream_id"], "sequence": value["sequence"] + 1,
                            "after": value["cursor"], "through": through, "events": events}
        batch(encoded(value["pending"]))
        await self.persist()
        await self.send()
        return True

    async def poll(self):
        try:
            while True:
                self.wake.clear()
                try:
                    more = await self.step()
                    self.error = None
                except Exception as exc:
                    self.error = exc.code if isinstance(exc, AuditError) else "audit_unavailable"
                    self.refuse(self.error)
                    more = False
                if more:
                    await asyncio.sleep(0)
                else:
                    try:
                        await asyncio.wait_for(self.wake.wait(), 1)
                    except TimeoutError:
                        pass
        finally:
            self.refuse("audit_unavailable")

    async def close(self):
        self.closed = True
        if self.task is not None:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
            self.task = None
        self.refuse("audit_unavailable")
