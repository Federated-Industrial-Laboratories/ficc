# SPDX-License-Identifier: Apache-2.0
"""Verify durable input streaming, immutable source binding, and lease enforcement."""

import base64
import concurrent.futures
import hashlib
import json
import os
import shutil
import sqlite3
import threading
from pathlib import Path

import pytest
from test_execution_ledger import NOW, fence, identity, plan, reading
from test_execution_local import settle, setup
from test_execution_protocol import request
from test_execution_provider import prepare as podman_prepare

from ficc.execution import inputs
from ficc.execution.ledger import Conflict
from ficc.execution.monitor import Monitor
from ficc.execution.protocol import (
    INPUT_CHUNK,
    Admission,
    InputChunk,
    InputObject,
    authorize,
    decode,
)
from ficc.execution.service import dispatch
from ficc.execution.spec import ObjectReference, Plan, Renewal, digest, encoded
from ficc.execution.supervisor import Supervisor
from ficc.execution.wire import REPLY


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def reference(data, index=0):
    return ObjectReference(id=identity(20000 + index), name=f"input-{index}.bin", bytes=len(data), digest=sha(data), delivery="stream")


def configure(tmp_path, data):
    s, values, provider, envelope, clock = setup(tmp_path, 1)
    for slot in s.settings.slots:
        slot.gid = os.getgid()
        Path(slot.mount).chmod(0o700)
    value = values[0]
    value.job.inputs = [reference(item, index) for index, item in enumerate(data)]
    return s, value, provider, envelope, clock


def admission(value):
    return Admission(plan=value, lease=Renewal(**fence(value).model_dump(), sequence=1, expires_at=NOW + 30))


def object_(value, index=0):
    return InputObject(**fence(value).model_dump(), object=value.job.inputs[index].id)


def chunk(value, offset, data, index=0):
    return InputChunk(**object_(value, index).model_dump(), offset=offset,
                      data=base64.b64encode(data).decode("ascii"), digest=sha(data))


def reply(s, action, **fields):
    message = decode(encoded(request(action, **fields)))
    return REPLY.validate_python(dispatch(s, message, s.settings.transport_uid)).model_dump()


def test_stream_reconnect_resumes_durable_offset_and_provider_links_verified_inputs(tmp_path):
    data = b"bounded input\n" * 180000
    s, value, provider, _envelope, _clock = configure(tmp_path, [data, b""])
    calls, original = [], provider.call

    def consume(provider_id, package, method, rows):
        calls.append(method)
        result = original(provider_id, package, method, rows)
        if method == "prepare":
            for ctx in rows:
                assert len(ctx["inputs"]) == 2
                destination = Path(ctx["directory"]) / "inputs"
                destination.mkdir()
                for item in ctx["plan"]["job"]["inputs"]:
                    podman_prepare.link_input(ctx, item, destination / item["name"], owner=os.getuid())
        elif method == "release":
            for ctx in rows:
                shutil.rmtree(ctx["directory"], ignore_errors=True)
        return result

    provider.call = consume
    try:
        s.prepare(admission(value))
        settle(s)
        record = s.ledger.get(value.attempt_id)
        staged = inputs.root(s.ctx(record))
        assert calls == [] and not s.snapshot(None)["attempts"][0]["ready"]
        assert s.input_status(object_(value, 1))["complete"]
        with pytest.raises(Conflict, match="runtime_preparing"):
            s.start(fence(value))
        # The acknowledgement is discarded, as if its connection was lost.
        first = chunk(value, 0, data[:INPUT_CHUNK])
        reply(s, "input_write", writes=[first.model_dump()])
        saved = reply(s, "input_status", objects=[object_(value).model_dump()])["results"][0]
        assert saved["offset"] == INPUT_CHUNK and not saved["complete"] and saved["digest"] == sha(data)
        with sqlite3.connect(s.ledger.path) as disk:
            durable = json.loads(disk.execute("SELECT value FROM attempts WHERE id=?", (value.attempt_id,)).fetchone()[0])
        assert durable["input_progress"][first.object]["offset"] == INPUT_CHUNK
        repeated = reply(s, "input_write", writes=[first.model_dump()])["results"][0]
        assert not repeated["ok"] and repeated["error"]["code"] == "input_offset_changed"
        assert s.prepare(admission(value))["input_progress"] == durable["input_progress"]
        assert not s.snapshot(None)["capacity"]["slots"][0]["available"]
        for offset in range(INPUT_CHUNK, len(data), INPUT_CHUNK):
            row = reply(s, "input_write", writes=[chunk(value, offset, data[offset:offset + INPUT_CHUNK]).model_dump()])["results"][0]
            assert row["ok"]
        assert row["complete"] and row["offset"] == len(data)
        settle(s)
        assert calls == ["probe", "prepare"] and s.snapshot(None)["attempts"][0]["ready"]
        ctx = s.ctx(s.ledger.get(value.attempt_id))
        for index, expected in enumerate((data, b"")):
            linked = Path(ctx["directory"]) / "inputs" / value.job.inputs[index].name
            original_path = staged / value.job.inputs[index].id
            assert linked.read_bytes() == expected and linked.stat().st_ino == original_path.stat().st_ino
            assert linked.stat().st_nlink == 2 and not linked.stat().st_mode & 0o222
        s.request_stop(fence(value))
        assert s.release(fence(value))["outcome"] == "cancelled" and not staged.exists()
        assert s.prepare(admission(value))["state"] == "released" and not provider.starts
    finally:
        s.close()


@pytest.mark.parametrize("change", ["digest", "disk", "storage_identity"])
def test_failed_source_or_disk_never_reaches_provider_and_retains_reservation(tmp_path, monkeypatch, change):
    s, value, provider, envelope, _clock = configure(tmp_path, [b"immutable"])
    try:
        s.prepare(admission(value))
        settle(s)
        s.input_write(chunk(value, 0, b"imm"))
        if change == "disk":
            envelope.fail_stop = True
            monkeypatch.setattr(inputs.os, "pwrite", lambda *_args: (_ for _ in ()).throw(OSError("Disk is full")))
        elif change == "storage_identity":
            path = inputs.root(s.ctx(s.ledger.get(value.attempt_id))) / value.job.inputs[0].id
            path.write_bytes(b"different")
        remainder = b"utable" if change != "digest" else b"utable".upper()
        with pytest.raises((Conflict, OSError)):
            s.input_write(chunk(value, 3, remainder))
        saved = s.ledger.get(value.attempt_id)
        assert saved["state"] == ("unknown" if change == "disk" else "failed")
        assert saved["slot"] is not None and not provider.states and not provider.starts
        assert not s.snapshot(None)["capacity"]["slots"][0]["available"]
        if change == "disk":
            with pytest.raises(Conflict, match="unconfirmed"):
                s.release(fence(value))
    finally:
        s.close()


@pytest.mark.parametrize("change", ["lease", "offer", "stop"])
def test_lost_authority_refuses_both_status_and_writes_without_advancing(tmp_path, change):
    s, value, provider, _envelope, clock = configure(tmp_path, [b"abcdef"])
    try:
        s.prepare(admission(value))
        settle(s)
        s.input_write(chunk(value, 0, b"abc"))
        if change == "lease":
            clock.value = reading(31)
        elif change == "offer":
            offered = s.offer()
            offered.projects = []
            offered.revision += 1
            s.ledger.save_offer(offered, 1)
        else:
            s.request_stop(fence(value))
        for operation, item in ((s.input_status, object_(value)), (s.input_write, chunk(value, 3, b"def"))):
            with pytest.raises(Conflict):
                operation(item)
        Monitor(s).tick()
        saved = s.ledger.get(value.attempt_id)
        assert saved["input_progress"][value.job.inputs[0].id]["offset"] == 3
        assert saved["slot"] is not None and not provider.starts
    finally:
        s.close()


def test_slow_disk_write_does_not_block_lease_monitor_and_cannot_release_live_storage(tmp_path, monkeypatch):
    s, value, provider, _envelope, clock = configure(tmp_path, [b"abcdef"])
    entered, unblock = threading.Event(), threading.Event()
    original = inputs.os.pwrite

    def slow(*args):
        entered.set()
        assert unblock.wait(5)
        return original(*args)

    try:
        s.prepare(admission(value))
        settle(s)
        monkeypatch.setattr(inputs.os, "pwrite", slow)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            writing = pool.submit(s.input_write, chunk(value, 0, b"abc"))
            assert entered.wait(2)
            try:
                clock.value = reading(31)
                pool.submit(Monitor(s).tick).result(timeout=1)
                assert s.ledger.get(value.attempt_id)["state"] == "expired"
                with pytest.raises(Conflict, match="unconfirmed"):
                    s.release(fence(value))
            finally:
                unblock.set()
            with pytest.raises(Conflict, match="expired"):
                writing.result(timeout=2)
        assert not provider.starts and s.release(fence(value))["outcome"] == "expired"
    finally:
        unblock.set()
        s.close()


def test_restart_keeps_partial_attempt_unknown_and_cannot_resume_or_replay(tmp_path):
    s, value, provider, envelope, clock = configure(tmp_path, [b"abcdef"])
    s.prepare(admission(value))
    settle(s)
    s.input_write(chunk(value, 0, b"abc"))
    ctx = s.ctx(s.ledger.get(value.attempt_id))
    configured, probe = s.settings, s.slot_probe
    s.close()
    restored = Supervisor(configured, provider, envelope=envelope, clock=clock, slot_probe=probe)
    try:
        Monitor(restored).recover()
        before = restored.ledger.get(value.attempt_id)
        assert before["state"] == "unknown" and before["cleanup_confirmed"]
        assert (inputs.root(ctx) / value.job.inputs[0].id).read_bytes() == b"abc"
        assert restored.prepare(admission(value)) == before
        with pytest.raises(Conflict, match="input_not_prepared"):
            restored.input_status(object_(value))
        assert not provider.starts and restored.release(fence(value))["outcome"] == "unknown"
        assert not inputs.root(ctx).exists()
    finally:
        restored.close()


def test_zero_length_digest_and_actual_slot_size_decide_admission(tmp_path):
    s, value, provider, _envelope, _clock = configure(tmp_path, [b""])
    value.job.inputs[0].digest = sha(b"different")
    try:
        s.prepare(admission(value))
        settle(s)
        saved = s.ledger.get(value.attempt_id)
        assert saved["state"] == "failed" and saved["slot"] is not None and not provider.states
    finally:
        s.close()
    other = tmp_path / "oversize"
    other.mkdir()
    s, value, provider, _envelope, _clock = configure(other, [b""])
    value.job.inputs[0].bytes = 40 * 1024**3
    try:
        saved = s.prepare(admission(value))
        assert saved["reason"] == "admission_rejected" and saved["slot"] is None and not provider.states
    finally:
        s.close()


def test_input_protocol_fences_identity_and_chunk_bounds_without_a_total_size_cap(tmp_path):
    s, value, _provider, _envelope, _clock = configure(tmp_path, [b"abcdef"])
    try:
        s.prepare(admission(value))
        settle(s)
        for field, changed in (("object", identity(90000)), ("generation", 2), ("plan_digest", sha(b"foreign"))):
            asked = object_(value).model_dump()
            asked[field] = changed
            observed = reply(s, "input_status", objects=[asked])["results"][0]
            assert not observed["ok"]
        write = chunk(value, 40 * 1024**3, b"a" * INPUT_CHUNK)
        message = decode(encoded(request("input_write", writes=[write.model_dump()])))
        assert message.writes[0].offset == 40 * 1024**3
        for peer in (s.settings.local_owner_uids[0], 99999):
            with pytest.raises(ValueError, match="transport"):
                authorize(message, peer, s.settings)
        second = {**write.model_dump(), "object": identity(90001)}
        with pytest.raises(ValueError, match="at most 1 MiB"):
            decode(encoded(request("input_write", writes=[write.model_dump(), second])))
        for change in ({"digest": sha(b"foreign")}, {"data": "!!!!"}, {"data": "YQ==\n"}, {"object": "../secret"}):
            with pytest.raises(ValueError):
                decode(encoded(request("input_write", writes=[{**write.model_dump(), **change}])))
    finally:
        s.close()


def test_default_local_input_keeps_existing_plan_bytes_and_digest():
    old = plan(0).model_dump()
    old["job"]["inputs"] = [{"id": identity(10000), "digest": sha(b"local"), "bytes": 5, "name": "input.bin"}]
    parsed = Plan.model_validate(old)
    assert encoded(parsed.model_dump()) == encoded(old) and parsed.digest() == digest(old)
    explicit = json.loads(json.dumps(old))
    explicit["job"]["inputs"][0]["delivery"] = "local"
    assert Plan.model_validate(explicit).model_dump() == old
    explicit["job"]["inputs"][0]["delivery"] = "stream"
    assert Plan.model_validate(explicit).digest() != parsed.digest()
