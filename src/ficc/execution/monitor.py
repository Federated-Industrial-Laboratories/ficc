# SPDX-License-Identifier: Apache-2.0
"""Fence expired work and release the payload barrier only after live checks pass."""

import os
import socket
from pathlib import Path

from .files import atomic_bytes
from .ledger import TERMINAL, Conflict
from .storage import processes
from .supervisor import fence


def notify(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        raise ValueError("The executor supervisor has no service-manager notification socket.")
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
        connection.connect(address)
        connection.sendall(message.encode("ascii"))


def marker(path):
    if path.exists():
        if path.is_symlink() or path.read_bytes() != b"release\n":
            raise ValueError("The payload release marker changed.")
        return
    atomic_bytes(path, b"release\n", 0o444)


def stop_reason(value, error, default):
    if value.get("pending_stop"):
        return value["pending_stop"]
    if isinstance(error, Conflict):
        return {"local_stopped": "cancelled", "execution_lease_expired": "expired"}.get(str(error), default)
    return default


class Monitor:
    def __init__(self, supervisor):
        self.supervisor = supervisor

    def recover(self):
        s = self.supervisor
        with s.lock:
            for value in s.ledger.retained():
                if value["state"] not in TERMINAL and not value["cleanup_confirmed"]:
                    s.finish(value, "supervisor_restarted")
            s.recovered = True

    def harvest(self):
        s = self.supervisor
        for identity, (operation, future) in list(s.pending.items()):
            if not future.done():
                continue
            del s.pending[identity]
            value = s.ledger.get(identity)
            try:
                result = future.result()
                s.current(value)
                if operation == "prepare":
                    s.ledger.annotate(fence(value), prepared_runtime=result)
                elif operation == "inputs":
                    value = s.ledger.annotate(fence(value), input_progress=result)
                    s.queue_preparation(value)
            except Exception as error:
                s.finish(value, stop_reason(value, error, "prepare_failed" if operation in {"prepare", "inputs"} else "start_unconfirmed"))

    def tick(self):
        s = self.supervisor
        with s.lock:
            self.harvest()
            for value in s.ledger.retained():
                if value["state"] == "unknown" and not value["cleanup_confirmed"]:
                    s.finish(value, value["reason"])
                    if not s.ledger.get(value["plan"]["attempt_id"])["cleanup_confirmed"]:
                        unit = s.envelope.inspect(s.ctx(value))
                        if unit.get("ActiveState") not in {None, "inactive", "failed"} or processes(s.slots[value["slot"]].uid):
                            raise ValueError("Workload cleanup is unconfirmed. Stop the supervisor and its dependent attempts.")
                    continue
                if value["state"] in TERMINAL | {"released", "unknown"}:
                    continue
                asked = fence(value)
                try:
                    s.current(value)
                except Exception as error:
                    reason = stop_reason(value, error, "expired")
                    s.ledger.annotate(asked, pending_stop=reason)
                    pending = s.pending.get(asked.attempt_id)
                    if pending is not None and pending[0] == "start":
                        s.envelope.stop(s.ctx(value))
                        raise ValueError("An in-flight runtime launch lost its lease. Stop the supervisor.")
                    if pending is None:
                        s.finish(value, reason)
                    continue
                if asked.attempt_id in s.pending or value["state"] == "prepared":
                    continue
                try:
                    self.observe(value)
                except Exception:
                    s.finish(value, "runtime_boundary_failed")

    def observe(self, value):
        s = self.supervisor
        ctx, asked = s.ctx(value), fence(value)
        current = s.call(ctx, "observe")
        unit = s.envelope.inspect(ctx)
        phase = current["phase"]
        if phase == "finished":
            s.finish(value)
            return
        if (unit.get("LoadState") == "not-found" or unit.get("ActiveState") in {"failed", "inactive"}
                or unit.get("ExecMainExitTimestampMonotonic", "0") not in {"", "0"}):
            s.finish(value, "runtime_outcome_unknown")
            return
        if phase == "ready" and not value.get("engine_released"):
            s.envelope.controls(ctx, value["prepared_runtime"])
            rows = current["device_probe"]
            expected = [(name, 0) for name in value["prepared_runtime"]["positive_devices"]]
            expected += [(name, 1) for name in value["prepared_runtime"]["negative_devices"]]
            if [(item["path"], item["errno"]) for item in rows] != expected:
                raise ValueError("The actual ancestor device access differs from the approved device set.")
            s.check(asked)
            marker(Path(ctx["directory"]) / "control/launch")
            s.ledger.annotate(asked, engine_released=True)
        elif phase == "payload" and not value.get("payload_released"):
            s.envelope.controls(ctx, value["prepared_runtime"])
            inspected = s.payload_gate(ctx, value["prepared_runtime"], current["payload_pid"])
            s.slot_probe(s.slots[value["slot"]], value["binding"])
            s.check(asked)
            s.ledger.started(asked, inspected)
            s.ledger.annotate(asked, payload_released=True)
            marker(Path(ctx["directory"]) / "control/release")
