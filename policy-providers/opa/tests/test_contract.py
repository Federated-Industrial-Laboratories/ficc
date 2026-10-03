# SPDX-License-Identifier: Apache-2.0
"""Check policy protocol, file safety and resource admission guards."""

import hashlib
import http.client
import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest
from conftest import envelope

from ficc_policy_opa import API_VERSION, files, isolation, prepare
from ficc_policy_opa.process import Output, reap
from ficc_policy_opa.runner import MAX_REQUEST, MAX_RESPONSE, Wire, decode, encode


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_envelope_and_decisions(count):
    request = envelope(count)
    assert json.loads(encode(request)) == {"input": request}
    result = [{"id": row["id"], "allow": index % 2 == 0, "reason": "checked"}
              for index, row in enumerate(request["requests"])]
    assert decode(json.dumps({"result": result}).encode(), request) == result
    assert API_VERSION == 1


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(version=True),
    lambda value: value.update(revision=True),
    lambda value: value.update(requests=[]),
    lambda value: value.update(requests=envelope(65)["requests"]),
    lambda value: value.update(extra=1),
    lambda value: value["requests"].append(value["requests"][0]),
    lambda value: value["requests"][0].update(authority=[]),
    lambda value: value["requests"][0]["labels"].update(text="x" * 300000),
])
def test_invalid_envelope(mutation):
    value = envelope(1)
    mutation(value)
    with pytest.raises(ValueError):
        encode(value)


@pytest.mark.parametrize("body", [
    b'{}', b'{"result":null}', b'{"result":[]}', b'{"result":[],"result":[]}',
    b'{"result":[{"id":"wrong","allow":true,"reason":"ok"}]}',
    b'{"result":[{"id":"request-0","allow":1,"reason":"ok"}]}',
    b'{"result":[{"id":"request-0","allow":true,"reason":"unsafe text"}]}',
    b'{"result":[{"id":"request-0","allow":true,"reason":"ok","extra":1}]}',
])
def test_invalid_decisions(body):
    with pytest.raises(ValueError):
        decode(body, envelope(1))


def decision_batch(count, defect):
    request = envelope(count)
    assert len({row["id"] for row in request["requests"]}) == count
    assert len({row["authority"]["identity"] for row in request["requests"]}) == count
    expected = [{"id": row["id"], "allow": index % 2 == 0, "reason": f"checked_{index}"}
                for index, row in enumerate(request["requests"])]
    changed = [dict(row) for row in expected]
    if defect == "allow_type":
        changed[-1]["allow"] = 1
    elif defect == "last_identity":
        changed[-1]["id"] = "another-request"
    elif defect == "tail_order":
        if count == 1:
            changed[0]["id"] = "another-batch"
        else:
            changed[-2:] = reversed(changed[-2:])
    elif defect == "missing":
        changed.pop()
    elif defect == "extra":
        changed.append({"id": "extra-request", "allow": True, "reason": "extra"})
    else:
        raise AssertionError("Unknown decision defect")
    return request, expected, changed


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("defect", ["allow_type", "last_identity", "tail_order", "missing", "extra"])
def test_decision_batch_rejects_corruption(count, defect):
    request, expected, changed = decision_batch(count, defect)
    assert decode(json.dumps({"result": expected}).encode(), request) == expected
    with pytest.raises(ValueError):
        decode(json.dumps({"result": changed}).encode(), request)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("defect", ["allow_type", "last_identity", "tail_order", "missing", "extra"])
def test_real_decision_batch_rejects_corruption(paths, configuration, count, defect):
    source, run = paths
    request, expected, changed = decision_batch(count, defect)
    (source / "rules.rego").write_text(
        "package ficc\ndecisions := data.responses[input.requests[0].labels.response]\n")
    (source / "data.json").write_text(json.dumps({"responses": {"valid": expected, "changed": changed}}))
    runner = prepare(configuration, source, run)
    try:
        request["requests"][0]["labels"]["response"] = "valid"
        assert runner.evaluate(request) == expected
        request["requests"][0]["labels"]["response"] = "changed"
        with pytest.raises(ValueError, match="unavailable or invalid"):
            runner.evaluate(request)
        assert runner.service.closed
        assert runner.service.process.poll() is not None
        assert runner.service.group is not None and isolation.empty(runner.service.group)
    finally:
        runner.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_invalid_input_keeps_evaluator(paths, configuration, count):
    request = envelope(count)
    expected = [{"id": row["id"], "allow": index % 2 == 0,
                 "reason": "allowed" if index % 2 == 0 else "denied"}
                for index, row in enumerate(request["requests"])]
    oversized = envelope(count)
    for row in oversized["requests"]:
        row["labels"]["text"] = "x" * (MAX_REQUEST // count)
    invalid_json = envelope(count)
    invalid_json["requests"][-1]["labels"]["value"] = object()
    runner = prepare(configuration, *paths)
    service = runner.service
    identity = (service.unit, service.process.pid, service.group)
    try:
        assert runner.evaluate(request) == expected
        for invalid in (oversized, invalid_json):
            with pytest.raises(ValueError, match="request"):
                runner.evaluate(invalid)
            assert runner.service is service
            assert (service.unit, service.process.pid, service.group) == identity
            assert not service.closed and service.process.poll() is None
            assert runner.evaluate(request) == expected
        print(json.dumps({"batch": count, "invalid_inputs": 2, "unit": service.unit,
                          "pid": service.process.pid, "same_evaluator": True}))
    finally:
        runner.close()
    assert service.closed and service.process.poll() is not None
    assert service.group is not None and isolation.empty(service.group)


def test_reason_code_boundary():
    request = envelope(1)
    item = {"id": "request-0", "allow": True, "reason": "a_.-" + "b" * 76}
    assert decode(json.dumps({"result": [item]}).encode(), request) == [item]
    item["reason"] += "x"
    with pytest.raises(ValueError):
        decode(json.dumps({"result": [item]}).encode(), request)


@pytest.mark.parametrize("change", ["symlink", "writable", "extra", "unsafe_run", "occupied"])
def test_unsafe_sources(paths, change):
    source, run = paths
    if change == "symlink":
        (source / "linked.rego").symlink_to(source / "rules.rego")
    elif change == "writable":
        (source / "rules.rego").chmod(0o666)
    elif change == "extra":
        (source / "config.yaml").write_text("services: []")
    elif change == "unsafe_run":
        run.chmod(0o755)
    else:
        (run / "used").touch()
    with pytest.raises(ValueError):
        files.directories(source, run)


@pytest.mark.parametrize("change", ["digest", "relative", "mode", "link", "extra", "fifo"])
def test_binary_identity(paths, change):
    source, run = paths
    binary = source.parent / "binary"
    binary.write_bytes(b"binary bytes")
    binary.chmod(0o500)
    config = {"binary": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    if change == "digest":
        config["sha256"] = "0" * 64
    elif change == "relative":
        config["binary"] = "binary"
    elif change == "mode":
        binary.chmod(0o777)
    elif change == "link":
        link = source.parent / "link"
        link.symlink_to(binary)
        config["binary"] = str(link)
    elif change == "extra":
        config["arguments"] = "--unsafe"
    else:
        binary.unlink()
        os.mkfifo(binary)
    with pytest.raises(ValueError, match="could not be prepared"):
        prepare(config, source, run)


def test_exact_binary_copy(paths):
    source, run = paths
    binary = source.parent / "binary"
    binary.write_bytes(b"exact bytes")
    binary.chmod(0o500)
    files.binary({"binary": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
                 run / "opa")
    binary.chmod(0o700)
    binary.write_bytes(b"later bytes")
    assert (run / "opa").read_bytes() == b"exact bytes"
    assert (run / "opa").stat().st_mode & 0o777 == 0o500


def test_capabilities():
    capabilities = json.loads(Path(isolation.__file__).with_name("capabilities.json").read_text())
    names = {item["name"] for item in capabilities["builtins"]}
    assert len(names) == 62
    assert {"eq", "equal", "neq", "internal.member_2", "object.get"} <= names
    assert not any(name.startswith(("http.", "net.", "opa.", "time.", "rand.", "uuid.", "io."))
                   for name in names)
    assert not {"print", "internal.print", "trace"} & names
    assert capabilities["allow_net"] == []


@pytest.mark.parametrize("control,value", [
    ("memory.max", "max"), ("memory.swap.max", "1"), ("pids.max", "max"),
    ("cpu.max", "max 100000"), ("cpu.max", "200000 100000"), ("cpu.max", "0 100000"),
])
def test_kernel_limits_are_required(tmp_path, monkeypatch, control, value):
    limits = {"memory.max": str(isolation.MEMORY_BYTES), "memory.swap.max": "0",
              "pids.max": "64", "cpu.max": "100000 100000"}
    for name, data in limits.items():
        (tmp_path / name).write_text(data)
    monkeypatch.setattr(isolation, "group_path", lambda values: tmp_path)
    assert isolation.enforcement(isolation.PROPERTIES) == tmp_path
    (tmp_path / control).write_text(value)
    with pytest.raises(ValueError, match="kernel"):
        isolation.enforcement(isolation.PROPERTIES)


def test_wire_deadline():
    sender, receiver = socket.socketpair()
    with sender, receiver:
        wire = Wire(receiver, time.monotonic() + 0.03)
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            wire.readinto(bytearray(1))
        assert time.monotonic() - start < 0.5


def test_wire_size_bound():
    sender, receiver = socket.socketpair()
    with sender, receiver:
        wire = Wire(receiver, time.monotonic() + 1)
        wire.received = MAX_RESPONSE + 16384
        sender.sendall(b"x")
        with pytest.raises(ValueError, match="wire limit"):
            wire.readinto(bytearray(1))


def test_process_output_limit():
    process = subprocess.Popen(["/usr/bin/python3", "-I", "-c", "print('x'*70000)"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"PATH": "/usr/bin"}, start_new_session=True)
    output = Output(process)
    deadline = time.monotonic() + 3
    try:
        with pytest.raises(ValueError, match="output exceeds"):
            while time.monotonic() < deadline:
                output.drain()
                time.sleep(0.005)
        assert all(len(data) <= 65536 for data in output.data)
    finally:
        reap(process)
        output.close()


def test_http_wire_deadline():
    sender, receiver = socket.socketpair()
    with sender, receiver:
        sender.sendall(b"HTTP/1.1 200 OK\r\nX-Slow:")
        with http.client.HTTPResponse(Wire(receiver, time.monotonic() + 0.03)) as response:
            with pytest.raises(TimeoutError):
                response.begin()
