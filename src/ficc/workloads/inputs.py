# SPDX-License-Identifier: Apache-2.0
"""Bind immutable datasets to leased contributor input streams with bounded memory."""

import asyncio
import base64
import hashlib
import re
from dataclasses import dataclass

from ..errors import Failure
from ..execution.spec import ObjectReference
from ..execution.wire import BatchReply, InputResult, Refused
from .commands import fence
from .schema import Attempt, Record

CHUNK = 1048576
PREFETCHES = 8


@dataclass
class Prefetch:
    attempt: Attempt
    job: Record
    object: str
    offset: int
    task: asyncio.Task
    discarded: bool = False


def references(dataset):
    values = []
    for index, source in enumerate(dataset["files"]):
        name = source["name"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
            name = f"input-{index:03}"
        values.append(ObjectReference(id=hashlib.sha256(
            f"{dataset['id']}:{index}:{source['sha256']}".encode()).hexdigest()[:32],
            digest="sha256:" + source["sha256"], bytes=source["size"], name=name, delivery="stream"))
    if len(values) > 64 or len({item.name for item in values}) != len(values):
        raise Failure("dataset_inputs", "Select a dataset with at most 64 files and distinct workload input names.", 409)
    return values


class Inputs:
    def __init__(self, queue):
        self.queue = queue
        self.pending: dict[str, Prefetch] = {}
        self.closed = False

    def discard(self, identity):
        work = self.pending.get(identity)
        if work is None:
            return
        work.discarded = True
        if work.task.done():
            self.pending.pop(identity, None)
        elif not work.task.cancelling():
            # Keep the slot until the source transport finishes cancellation and closes its worker.
            work.task.cancel()

    def discard_job(self, identity):
        for work in list(self.pending.values()):
            if work.job.id == identity:
                self.discard(work.attempt.id)

    def discard_node(self, identity):
        for work in list(self.pending.values()):
            if work.attempt.node_id == identity:
                self.discard(work.attempt.id)

    def stop(self):
        self.closed = True
        for identity in list(self.pending):
            self.discard(identity)

    async def close(self):
        tasks = [work.task for work in self.pending.values()]
        self.stop()
        await asyncio.gather(*tasks, return_exceptions=True)

    def current(self, attempt, job):
        current = self.queue.records.attempt(attempt.id)
        record = self.queue.records.get(job.id)
        if (self.closed or record.current_attempt != attempt.id or current.state != "prepared"
                or current.start_requested or fence(current) != fence(attempt)
                or record.request.dataset != job.request.dataset):
            raise Failure("attempt_changed", "The input read no longer belongs to the current prepared attempt.", 409)
        self.queue.runner.authority(current, starting=True)
        return record

    def prune(self):
        for work in list(self.pending.values()):
            try:
                self.current(work.attempt, work.job)
            except (Failure, ValueError):
                self.discard(work.attempt.id)

    async def read(self, attempt, job, index, offset):
        chunks = bytearray()
        item = job.request.job.inputs[index]
        def authority():
            return self.queue.authority.current(self.current(attempt, job).delegation)
        while len(chunks) < CHUNK and offset + len(chunks) < item.bytes:
            _header, data = await self.queue.service.datasets.read(job.request.dataset.id, index, authority,
                offset + len(chunks), min(262144, CHUNK - len(chunks)))
            chunks.extend(data)
        self.current(attempt, job)
        return chunks

    def prefetch(self, attempt, job, index, offset):
        task = asyncio.create_task(self.read(attempt, job, index, offset))
        work = Prefetch(attempt, job, job.request.job.inputs[index].id, offset, task)
        self.pending[attempt.id] = work
        def finished(task):
            if not task.cancelled():
                task.exception()  # Retain failures for the maintenance poll without unowned task errors.
            if work.discarded and self.pending.get(attempt.id) is work:
                self.pending.pop(attempt.id)
        task.add_done_callback(finished)

    def dataset(self, request, authority):
        selected = request.dataset
        if selected is None:
            return None
        value = self.queue.service.datasets.get(selected.id, authority)
        if value["manifest_digest"] != selected.manifest_digest:
            raise Failure("dataset_changed", "The selected dataset manifest differs from the submission.", 409)
        self.queue.service.datasets.safety.require(value)
        return value

    def bind(self, request, delegation):
        value = self.dataset(request, lambda: self.queue.authority.current(delegation))
        if value is None:
            if any(item.delivery == "stream" for item in request.job.inputs):
                raise Failure("dataset_required", "Streamed inputs require a registered project dataset.")
            return request
        inputs = references(value)
        if request.job.inputs and request.job.inputs != inputs:
            raise Failure("dataset_inputs", "The requested inputs differ from the selected dataset.", 409)
        if sum(item.bytes for item in inputs) > request.job.limits.storage_bytes:
            raise Failure("dataset_capacity", "Input data exceeds this workload's storage allowance.", 409)
        sensitive = request.job.sensitive or self.queue.service.datasets.safety.effective(value)["sensitive"]
        return request.model_copy(update={"job": request.job.model_copy(update={"inputs": inputs, "sensitive": sensitive})})

    def check(self, job):
        value = self.dataset(job.request, lambda: self.queue.authority.current(job.delegation))
        if value is not None and references(value) != job.request.job.inputs:
            raise Failure("dataset_inputs", "The stored workload no longer matches its dataset manifest.", 409)
        return self.queue.service.datasets.safety.require(value) if value is not None else None

    async def advance(self, identity, attempts):
        queue = self.queue
        if self.closed:
            return False
        retained = {attempt.id for attempt in attempts if attempt.state == "prepared" and not attempt.start_requested
                    and not queue.commands.observed.get(attempt.id, {}).get("ready")}
        for work in list(self.pending.values()):
            if work.attempt.node_id == identity and work.attempt.id not in retained:
                self.discard(work.attempt.id)
        for attempt in attempts:
            if attempt.state != "prepared" or attempt.start_requested:
                continue
            job = queue.records.get(attempt.job_id)
            if job.request.dataset is None or queue.commands.observed.get(attempt.id, {}).get("ready"):
                continue
            try:
                if await self.transfer(identity, attempt, job):
                    return True
            except Failure as exc:
                self.discard(attempt.id)
                if exc.code in {"inputs_preparing", "input_offset_changed", "input_busy", "input_not_prepared", "executor_busy"}:
                    continue
                # A missing acknowledgement is reconciled from the durable input offset.
                if exc.status >= 500 or exc.code in {"contributor_disconnected", "node_lease_changed"}:
                    raise
                with queue.service.store.lock, queue.service.store.db:
                    current = queue.records.get(job.id)
                    if not current.cancelled:
                        queue.records.cancel(current.id, current.revision)
                        queue.service.store.audit("workload.input", current.id, exc.code, current.actor,
                            subject_id=current.subject_id, project_id=current.project_id)
        return False

    async def transfer(self, identity, attempt, job):
        queue = self.queue
        def check():
            self.current(attempt, job)
        check()
        inputs = job.request.job.inputs
        if not inputs:
            return False
        reply = await queue.commands.call(identity, "input_status", {
            "objects": [{**fence(attempt), "object": item.id} for item in inputs]}, check)
        rows = self.progress(reply, attempt, inputs)
        progress = {"received_bytes": sum(row.offset for row in rows), "total_bytes": sum(item.bytes for item in inputs),
                    "route": "controller_relay"}
        queue.commands.observed.setdefault(attempt.id, {})["inputs"] = progress
        for index, (item, row) in enumerate(zip(inputs, rows, strict=True)):
            if row.complete:
                continue
            offset = row.offset
            work = self.pending.get(attempt.id)
            if work and (work.object != item.id or work.offset != offset or fence(work.attempt) != fence(attempt)):
                self.discard(attempt.id)
                work = self.pending.get(attempt.id)
            if work is None:
                if len(self.pending) < PREFETCHES:
                    self.prefetch(attempt, job, index, offset)
                return False
            if work.discarded or not work.task.done():
                return False
            try:
                chunks = work.task.result()
                check()
                response = await queue.commands.call(identity, "input_write", {"writes": [{**fence(attempt),
                    "object": item.id, "offset": offset, "data": base64.b64encode(chunks).decode(),
                    "digest": "sha256:" + hashlib.sha256(chunks).hexdigest()}]}, check)
                written = self.progress(response, attempt, [item])[0]
                if written.offset != offset + len(chunks):
                    raise Failure("executor_response", "The executor acknowledged a different input byte range.", 502)
                progress["received_bytes"] = sum(current.offset for current in rows) + written.offset - offset
            finally:
                self.discard(attempt.id)
            return True
        self.discard(attempt.id)
        return False

    def progress(self, reply, attempt, inputs):
        if not isinstance(reply, BatchReply) or len(reply.results) != len(inputs):
            raise Failure("executor_response", "The executor returned an invalid input receipt.", 502)
        values = []
        for row, item in zip(reply.results, inputs, strict=True):
            if row.model_dump(include={"attempt_id", "generation", "plan_digest"}) != fence(attempt):
                raise Failure("executor_response", "The executor input receipt belongs to a different attempt.", 502)
            if isinstance(row, Refused):
                raise Failure(row.error.code, row.error.message, 409)
            if (not isinstance(row, InputResult)
                    or row.object != item.id or row.bytes != item.bytes or row.digest != item.digest
                    or row.complete and row.offset != item.bytes):
                raise Failure("executor_response", "The executor input receipt differs from the immutable plan.", 502)
            values.append(row)
        return values
