# SPDX-License-Identifier: Apache-2.0
"""Check known protocol-two examples with bounded interactive host fixtures."""

import copy
import json
import os
import re
import select
import signal
import struct
import subprocess
import time

MAXIMUM = 2 * (1024 * 1024 + 4)


def frame(value):
    data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
    return struct.pack(">I", len(data)) + data


def exact(fd, size, deadline):
    value = bytearray()
    while len(value) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise AssertionError("Example response timed out")
        chunk = os.read(fd, size - len(value))
        if not chunk:
            raise AssertionError("Example response ended early")
        value.extend(chunk)
    return bytes(value)


def read(process, deadline, received):
    size = struct.unpack(">I", exact(process.stdout.fileno(), 4, deadline))[0]
    assert 0 < size <= 1024 * 1024
    received[0] += size + 4
    assert received[0] <= MAXIMUM
    value = json.loads(exact(process.stdout.fileno(), size, deadline))
    assert isinstance(value, dict)
    return value


def results(targets, errors=False):
    return [
        {
            "target": target,
            **(
                {"error": {"code": "denied", "message": "Fixture refusal"}}
                if errors or index == 63
                else {
                    "data": {
                        "id": target,
                        "index": index,
                        "state": "ready",
                        "text": 'Quote " and snow 雪',
                    }
                }
            ),
        }
        for index, target in enumerate(targets)
    ]


def exchange(command, count=1, mode="ok", request_changes=None, hello_changes=None):
    identity = "a" * 32
    selected = [f"target-{index}" for index in range(count)]
    request = {
        "version": 2,
        "type": "invoke",
        "id": identity,
        "action": "read",
        "targets": selected,
        "parameters": {},
    }
    hello = {"version": 2, "type": "hello", "host_api": 1}
    request.update(request_changes or {})
    hello.update(hello_changes or {})
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/tmp",
        env={"PATH": os.defpath, "LANG": "C.UTF-8"},
        bufsize=0,
        start_new_session=True,
    )
    deadline, received = time.monotonic() + 5, [0]
    try:
        process.stdin.write(frame(hello) + frame(request))
        process.stdin.flush()
        if request_changes or hello_changes:
            process.stdin.close()
            assert process.wait(timeout=5) != 0
            assert process.stdout.read(MAXIMUM + 1) == b""
            return
        assert read(process, deadline, received) == {"version": 2, "type": "hello", "protocol": 2}
        broker = read(process, deadline, received)
        assert set(broker) == {
            "version",
            "type",
            "id",
            "invocation_id",
            "primitive",
            "targets",
            "parameters",
        }
        assert broker["version"] == 2 and broker["type"] == "broker"
        assert re.fullmatch("[0-9a-f]{32}", broker["id"]) and broker["id"] != identity
        assert broker["invocation_id"] == identity and broker["targets"] == selected
        assert broker["primitive"] == "system.resources.read" and broker["parameters"] == {}
        expected = results(selected, errors=mode == "errors")
        reply = {
            "version": 2,
            "type": "broker-result",
            "id": broker["id"],
            "invocation_id": identity,
            "results": copy.deepcopy(expected),
        }
        if mode == "wrong-id":
            reply["id"] = "f" * 32
        elif mode == "wrong-invocation":
            reply["invocation_id"] = "f" * 32
        elif mode == "wrong-version":
            reply["version"] = 1
        elif mode == "boolean-version":
            reply["version"] = True
        elif mode == "unknown-field":
            reply["secret"] = "forbidden"
        elif mode == "wrong-type":
            reply["type"] = "invoke"
        elif mode == "missing-result":
            reply["results"] = []
        elif mode == "duplicate-result":
            reply["results"] *= 2
        elif mode == "outside-result":
            reply["results"][0]["target"] = "outside"
        elif mode == "both-outcomes":
            reply["results"][0]["error"] = {"code": "denied", "message": "Denied"}
        elif mode == "no-outcome":
            reply["results"][0] = {"target": selected[0]}
        elif mode == "invalid-error":
            reply["results"][0] = {
                "target": selected[0],
                "error": {"code": "bad/code", "message": "x"},
            }
        elif mode == "long-error":
            reply["results"][0] = {
                "target": selected[0],
                "error": {"code": "denied", "message": "x" * 1025},
            }
        elif mode == "invalid-row":
            reply["results"] = [None]
        elif mode in ("cancel", "wrong-cancel"):
            reply = {
                "version": 2,
                "type": "cancel",
                "id": identity if mode == "cancel" else "f" * 32,
            }
        encoded = frame(reply)
        if mode == "truncated":
            encoded = encoded[:-1]
        elif mode == "oversized":
            encoded = struct.pack(">I", 1024 * 1024 + 1)
        elif mode == "invalid-json":
            encoded = struct.pack(">I", 1) + b"!"
        elif mode == "invalid-utf8":
            encoded = struct.pack(">I", 1) + b"\xff"
        process.stdin.write(encoded)
        process.stdin.close()
        if mode in ("ok", "errors"):
            assert read(process, deadline, received) == {
                "version": 2,
                "type": "result",
                "id": identity,
                "results": expected,
            }
            assert process.wait(timeout=5) == 0
        else:
            assert process.wait(timeout=5) != 0, mode
        assert process.stdout.read(MAXIMUM + 1) == b"", mode
        assert len(process.stderr.read(65537)) <= 65536
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def cases(command):
    count = 0
    for size in (1, 64):
        for mode in ("ok", "errors"):
            exchange(command, size, mode)
            count += 1
    for mode in (
        "wrong-id",
        "wrong-invocation",
        "wrong-version",
        "boolean-version",
        "unknown-field",
        "wrong-type",
        "missing-result",
        "duplicate-result",
        "outside-result",
        "both-outcomes",
        "no-outcome",
        "invalid-error",
        "long-error",
        "invalid-row",
        "cancel",
        "wrong-cancel",
        "truncated",
        "oversized",
        "invalid-json",
        "invalid-utf8",
    ):
        exchange(command, mode=mode)
        count += 1
    for request in (
        {"id": "g" * 32},
        {"id": "a" * 31},
        {"action": "/bin/sh"},
        {"targets": []},
        {"targets": ["a", "a"]},
        {"version": 1},
        {"extra": "unknown"},
    ):
        exchange(command, request_changes=request)
        count += 1
    exchange(command, hello_changes={"version": 1})
    return count + 1
