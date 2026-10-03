# SPDX-License-Identifier: Apache-2.0
"""Coordinate durable local admission with bounded provider work and current authority."""

import concurrent.futures
import logging
import threading
from pathlib import Path

from . import gate, inputs, storage
from .clock import Clock, active
from .envelope import Envelope, context
from .ledger import TERMINAL, Conflict, Ledger
from .offer import Offer, validate_offer
from .spec import AttemptResult, Fence, Plan, digest


def fence(value):
    return Fence(attempt_id=value["plan"]["attempt_id"], generation=value["plan"]["generation"],
                 plan_digest=value["plan_digest"])


def public(value):
    result = AttemptResult(**fence(value).model_dump(), **{key: value[key] for key in
        ("state", "reason", "exit_code", "output_bytes", "error_bytes", "cleanup_confirmed")}).model_dump()
    result.update({name: value["plan"][name] for name in ("job_id", "project_id", "offer_revision")})
    result.update(lease_sequence=value["lease_sequence"], lease_expires_at=value["lease_expires_at"],
                  ready=bool(value.get("prepared_runtime")) and value["state"] == "prepared",
                  outcome=value.get("outcome"))
    return result


class Supervisor:
    def __init__(self, settings, providers, *, envelope=None, clock=None, slot_probe=None, payload_gate=None):
        self.settings, self.providers = settings, providers
        self.envelope, self.clock = envelope or Envelope(), clock or Clock()
        self.slot_probe, self.payload_gate = slot_probe or storage.verify, payload_gate or gate.inspect
        self.ledger = Ledger(Path(settings.state), settings.installation_id)
        self.slots = {slot.id: slot for slot in settings.slots}
        self.lock = threading.RLock()
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(self.slots)))
        self.pending = {}
        self.inputs, self.input_busy = inputs.Inputs(), set()
        self.recovered = False
        if self.ledger.offer() is None:
            self.ledger.save_offer(settings.initial_offer, 0)
        offer = self.offer()
        if offer.mode != settings.mode:
            raise ValueError("The retained local offer has another installation mode.")
        validate_offer(offer, settings.ceiling)

    def offer(self):
        value = self.ledger.offer()
        if value is None:
            raise Conflict("The retained local contribution offer is absent.")
        return value

    def ctx(self, value):
        if value["slot"] is None:
            raise Conflict("The attempt storage has already been released.")
        result = context(self.settings, self.slots[value["slot"]], value)
        result["inputs"] = inputs.capabilities(result, value.get("input_progress", {}))
        if value.get("prepared_runtime"):
            result["prepared"] = value["prepared_runtime"]
        return result

    def call(self, ctx, method):
        runtime = ctx["plan"]["job"]["runtime"]
        return self.providers.call(runtime["provider"], runtime["package_digest"], method, [ctx])[0]

    def current(self, value):
        now = self.clock.read()
        if not active(value, now):
            raise Conflict("execution_lease_expired")
        if value.get("pending_stop"):
            raise Conflict("execution_stop_requested")
        plan = Plan.model_validate(value["plan"])
        reason = self.offer().refusal(plan.project_id, plan.job, now.wall, continuing=True)
        if reason:
            raise Conflict(reason)
        return now

    def check(self, asked):
        value = self.ledger.fenced(asked.attempt_id, asked.generation, asked.plan_digest)
        self.current(value)
        return value

    def bind(self, request):
        if (request.installation_id != self.settings.installation_id or request.ledger_id != self.ledger.identity
                or request.admission_version != 1):
            raise Conflict("The admission request belongs to another installation or ledger.")

    def prepare(self, admission):
        with self.lock:
            plan = admission.plan
            self.settings.check_identity(plan)
            before = self.ledger.get(plan.attempt_id)
            if before is not None:
                return self.ledger.fenced(plan.attempt_id, plan.generation, plan.digest())
            try:
                held = {item["slot"] for item in self.ledger.retained()}
                choices = [slot for slot in self.slots.values() if slot.id not in held
                           and slot.storage_bytes <= plan.job.limits.storage_bytes
                           and slot.storage_inodes <= plan.job.limits.storage_inodes
                           and sum(item.bytes for item in plan.job.inputs) <= slot.storage_bytes]
                if not choices:
                    raise Conflict("No available finite storage slot fits this job's admitted maximum.")
                slot = sorted(choices, key=lambda item: (item.storage_bytes, item.storage_inodes, item.id))[0]
                binding = self.slot_probe(slot, idle=True)
                value, fresh = self.ledger.admit(admission, slot.id, binding, self.clock.read(), self.settings.maximum_lease_seconds)
            except (Conflict, ValueError, OSError):
                # No provider method can run before the durable reservation.
                return self.ledger.reject(plan, self.clock.read().wall)
            if fresh:
                self.queue_preparation(value)
            return value

    def queue_preparation(self, value):
        asked = fence(value)
        if (asked.attempt_id in self.pending or value["state"] != "prepared"
                or value.get("prepared_runtime") or value.get("pending_stop")):
            return
        ctx = self.ctx(value)
        ctx["check"] = lambda: self.check(asked)
        if inputs.references(ctx) and "input_progress" not in value:
            self.pending[asked.attempt_id] = ("inputs", self.pool.submit(self.inputs.initialize, ctx))
        elif inputs.complete(ctx, value.get("input_progress", {})):
            self.pending[asked.attempt_id] = ("prepare", self.pool.submit(self.prepare_runtime, ctx))

    def prepare_runtime(self, ctx):
        ctx["check"]()
        if self.call(ctx, "probe").get("ready") is not True:
            raise ValueError("The installed runtime is not ready for this attempt.")
        ctx["check"]()
        return self.call(ctx, "prepare")

    def input_record(self, request):
        value = self.check(request)
        if value["state"] != "prepared":
            raise Conflict("input_not_prepared")
        item = next((item for item in value["plan"]["job"]["inputs"] if item["id"] == request.object
                     and item.get("delivery", "local") == "stream"), None)
        if item is None:
            raise Conflict("input_not_declared")
        receipt = value.get("input_progress", {}).get(request.object)
        if receipt is None:
            raise Conflict("inputs_preparing")
        return value, item, receipt

    def input_status(self, request):
        with self.lock:
            _value, item, receipt = self.input_record(request)
            return {"object": item["id"], "offset": receipt["offset"], "bytes": item["bytes"],
                    "digest": item["digest"], "complete": receipt["complete"]}

    def input_write(self, request):
        data = request.decoded()
        with self.lock:
            value, item, receipt = self.input_record(request)
            if request.attempt_id in self.input_busy:
                raise Conflict("input_busy")
            if request.offset != receipt["offset"]:
                raise Conflict("input_offset_changed")
            if len(data) > item["bytes"] - request.offset or not data and item["bytes"]:
                raise Conflict("input_size_mismatch")
            if receipt["complete"]:
                return self.input_status(request)
            self.input_busy.add(request.attempt_id)
            ctx = self.ctx(value)
            ctx["check"] = lambda: self.input_record(request)
        try:
            self.slot_probe(self.slots[value["slot"]], value["binding"], idle=True)
            saved, hashed = self.inputs.write(ctx, item, receipt, request, data)
            with self.lock:
                current, _item, _receipt = self.input_record(request)
                value = self.ledger.annotate(request, input_progress={**current["input_progress"], item["id"]: saved})
                self.inputs.committed(request, hashed)
                self.queue_preparation(value)
                return self.input_status(request)
        except Exception as exc:
            with self.lock:
                current = self.ledger.fenced(request.attempt_id, request.generation, request.plan_digest)
                reason = "expired" if isinstance(exc, Conflict) and not isinstance(exc, inputs.InputFailure) else "prepare_failed"
                self.request_stop(request, current.get("pending_stop") or reason)
            raise
        finally:
            with self.lock:
                self.input_busy.discard(request.attempt_id)

    def reject_absent(self, plan, *, legacy=False):
        with self.lock:
            self.settings.check_identity(plan)
            before = self.ledger.get(plan.attempt_id)
            if before is not None:
                return self.ledger.fenced(plan.attempt_id, plan.generation, plan.digest())
            observed = None
            if legacy:
                observed = []
                for slot in self.slots.values():
                    binding = self.slot_probe(slot, idle=True)
                    ctx = context(self.settings, slot, {"plan": plan.model_dump(), "plan_digest": plan.digest(), "binding": binding})
                    path = Path(ctx["directory"])
                    staged = inputs.root(ctx)
                    if path.exists() or path.is_symlink() or staged.exists() or staged.is_symlink():
                        raise Conflict("The absent attempt has retained storage. Inspect it before reconciliation.")
                    observed.append({"binding": binding, "workload": self.envelope.idle(ctx)})
            return self.ledger.reject(plan, self.clock.read().wall, observation=observed)

    def start(self, asked):
        with self.lock:
            value = self.ledger.fenced(asked.attempt_id, asked.generation, asked.plan_digest)
            if value["state"] == "prepared" and not value.get("prepared_runtime"):
                raise Conflict("runtime_preparing")
            value, first = self.ledger.start_requested(asked, self.clock.read())
            if first:
                self.pending[asked.attempt_id] = ("start", self.pool.submit(self.launch, asked))
            return value

    def launch(self, asked):
        value = self.check(asked)
        ctx = self.ctx(value)
        self.slot_probe(self.slots[value["slot"]], value["binding"], idle=True)
        prepared = self.call(ctx, "start")
        self.check(asked)
        self.envelope.launch(ctx, prepared)
        self.check(asked)
        return prepared

    def renew(self, request):
        with self.lock:
            value = self.ledger.fenced(request.attempt_id, request.generation, request.plan_digest)
            if value.get("pending_stop"):
                raise Conflict("An execution stop is already pending.")
            return self.ledger.renew(request, self.clock.read(), self.settings.maximum_lease_seconds)

    def set_offer(self, request):
        with self.lock, self.ledger.lock, self.ledger.db:
            validate_offer(request.settings, self.settings.ceiling)
            value = Offer(**request.settings.model_dump(), revision=request.expected_revision + 1,
                          mode=self.settings.mode, control=request.control)
            self.ledger.save_offer(value, request.expected_revision)
            if value.control == "stopped":
                for attempt in self.ledger.retained():
                    if attempt["state"] not in TERMINAL | {"unknown", "released"} and not attempt.get("pending_stop"):
                        self.ledger.annotate(fence(attempt), pending_stop="cancelled")
            return value.model_dump()

    def request_stop(self, asked, reason="cancelled"):
        with self.lock:
            value = self.ledger.fenced(asked.attempt_id, asked.generation, asked.plan_digest)
            if value["state"] in TERMINAL | {"released"} or value["state"] == "unknown" and value["cleanup_confirmed"]:
                return value
            if value["state"] != "unknown":
                self.ledger.annotate(asked, pending_stop=reason)
            if asked.attempt_id not in self.pending:
                self.finish(value, reason)
            return self.ledger.get(asked.attempt_id)

    def finish(self, value, reason=None):
        if value["state"] == "unknown" and value["cleanup_confirmed"]:
            return
        ctx = self.ctx(value)
        observed = {}
        if value.get("prepared_runtime"):
            try:
                observed = self.call(ctx, "observe")
            except Exception:
                reason = "runtime_outcome_unknown"
        stage = "process stop"
        try:
            self.envelope.stop(ctx)
            stage = "storage verification"
            self.slot_probe(self.slots[value["slot"]], value["binding"], idle=True)
            if value.get("prepared_runtime"):
                try:
                    stopped = self.call(ctx, "stop")
                    if stopped.get("phase") == "finished":
                        observed = stopped
                except Exception:
                    reason = "runtime_outcome_unknown"
            state, code = "unknown", None
            if observed.get("phase") == "finished" and value.get("payload_released"):
                code = observed["exit_code"]
                state = "succeeded" if code == 0 else "failed"
                reason = None
            elif reason in {"cancelled", "expired"}:
                state = reason
            elif reason == "prepare_failed":
                state = "failed"
            result = AttemptResult.model_validate({**fence(value).model_dump(), "state": state, "reason": reason,
                "exit_code": code, "output_bytes": observed.get("stdout_bytes", 0),
                "error_bytes": observed.get("stderr_bytes", 0), "cleanup_confirmed": True})
        except Exception as exc:
            logging.getLogger(__name__).warning("Executor cleanup failed during %s (%s).", stage, type(exc).__name__)
            result = AttemptResult(**fence(value).model_dump(), state="unknown", reason="cleanup_unconfirmed", exit_code=None,
                                   output_bytes=0, error_bytes=0, cleanup_confirmed=False)
        if value["state"] == "unknown":
            # A cleanup retry cannot replace the recorded uncertain outcome.
            result = result.model_copy(update={key: value[key] for key in
                ("state", "reason", "exit_code", "output_bytes", "error_bytes")})
        self.ledger.finish(result)

    def collect(self, request):
        value = self.ledger.fenced(request.attempt_id, request.generation, request.plan_digest)
        if value["slot"] is None and value.get("admission_rejection") and value["state"] != "released":
            if request.object not in {"stdout", "stderr"} or request.offset != 0:
                raise Conflict("This rejected attempt has no stored output at that position.")
            return {"object": request.object, "offset": 0, "data": "", "next_offset": 0,
                    "total_bytes": 0, "eof": True, "complete": True,
                    "identity": digest({"rejected_plan": value["plan_digest"], "object": request.object})}
        ctx = self.ctx(value)
        self.slot_probe(self.slots[value["slot"]], value["binding"])
        return self.call({**ctx, "read": request.model_dump(), "cleanup_confirmed": value["cleanup_confirmed"]}, "collect")

    def release(self, asked):
        with self.lock:
            value = self.ledger.fenced(asked.attempt_id, asked.generation, asked.plan_digest)
            if value["state"] == "released":
                return value
            if (value["state"] not in TERMINAL | {"unknown"} or not value["cleanup_confirmed"]
                    or asked.attempt_id in self.pending or asked.attempt_id in self.input_busy):
                raise Conflict("The attempt outcome or cleanup remains unconfirmed.")
            if value["slot"] is None and value.get("admission_rejection"):
                return self.ledger.release(asked)
            ctx = self.ctx(value)
            self.slot_probe(self.slots[value["slot"]], value["binding"], idle=True)
            self.call(ctx, "release")
            if inputs.references(ctx):
                self.inputs.release(ctx)
            self.slot_probe(self.slots[value["slot"]], value["binding"], idle=True)
            return self.ledger.release(asked)

    def snapshot(self, after):
        attempts, more = self.ledger.page(after)
        held = {value["slot"]: value for value in self.ledger.retained()}
        slots = []
        for slot in self.slots.values():
            value = held.get(slot.id)
            reason = None if value is None else "reservation_retained"
            if value is None:
                try:
                    self.slot_probe(slot, idle=True)
                except Exception:
                    reason = "slot_unavailable"
            slots.append({"id": slot.id, "generation": slot.generation, "storage_bytes": slot.storage_bytes,
                          "storage_inodes": slot.storage_inodes, "available": reason is None, "reason": reason})
        offer = self.offer()
        resources = offer.limits.model_dump()
        for key in ("cpu_millis", "memory_bytes", "swap_bytes", "processes", "storage_bytes", "storage_inodes"):
            used = sum(value["plan"]["job"]["limits"][key] for value in held.values()
                       if key.startswith("storage_") or not value["cleanup_confirmed"])
            resources[key] = max(0, resources[key] - used)
        occupied = {device for value in held.values() if not value["cleanup_confirmed"]
                    for device in value["plan"]["job"]["limits"]["gpu_devices"]}
        resources["gpu_devices"] = [device for device in resources["gpu_devices"] if device not in occupied]
        return {"installation_id": self.settings.installation_id, "deployment_id": self.settings.deployment_id,
                "ledger_id": self.ledger.identity, "admission_version": 1,
                "node_id": self.settings.node_id, "maximum_lease_seconds": self.settings.maximum_lease_seconds,
                "offer": offer.model_dump(),
                "capacity": {"slots": slots, "providers": [{"id": item.id, "package_digest": item.package_digest}
                                                            | {"available": True, "reason": None}
                                                            for item in self.settings.providers], "available": resources},
                "attempts": [public(value) for value in attempts],
                "next": attempts[-1]["plan"]["attempt_id"] if more else None}

    def close(self):
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.ledger.close()
