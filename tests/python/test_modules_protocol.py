# SPDX-License-Identifier: Apache-2.0
"""Verify strict framing and complete N=1 and N=64 batch correspondence."""

import struct

import pytest

from ficc.errors import Failure
from ficc.modules import protocol
from ficc.modules.validation import loads


def reply(request_id, results):
    return protocol.frame({"version": 1, "type": "hello", "protocol": 1}) + protocol.frame({
        "version": 1, "type": "result", "id": request_id, "results": results})


@pytest.mark.parametrize("count", [1, 64])
def test_batches_preserve_target_identity_and_request_order(count):
    targets = [f"workspace-{i}" for i in range(count)]
    request_id, payload = protocol.request("read", targets, {})
    hello, invocation = protocol.frames(payload)
    assert hello == {"version": 1, "type": "hello", "host_api": 1}
    assert invocation["targets"] == targets
    results = [{"target": target, "data": {"position": i}} if i % 2 == 0 else
               {"target": target, "error": {"code": "unavailable", "message": "Unavailable"}}
               for i, target in enumerate(targets)]
    assert protocol.response(reply(request_id, list(reversed(results))), request_id, targets)["results"] == results


@pytest.mark.parametrize("results", [[], [{"target": "other", "data": 1}],
    [{"target": "a", "data": 1}, {"target": "a", "data": 2}],
    [{"target": "a", "data": 1, "error": {"code": "bad", "message": "Both"}}],
    [{"target": "a", "data": 1, "extra": "bad"}], [{"target": "a"}]])
def test_reject_missing_duplicate_unknown_or_ambiguous_results(results):
    with pytest.raises(Failure):
        protocol.response(reply("request", results), "request", ["a"])


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x00\x00\x00", struct.pack(">I", 1048577),
    b'\x00\x00\x00\x10{}', protocol.frame({"type": "broker-call"}),
    protocol.frame({}) * 3])
def test_reject_truncated_extra_and_broker_frames(data):
    with pytest.raises(Failure):
        protocol.response(data, "request", ["a"])


@pytest.mark.parametrize("data", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
    b'{"a":9007199254740992}', b'[' * 20 + b'0' + b']' * 20, b'"\xff"'])
def test_json_rejects_ambiguous_or_unbounded_values(data):
    with pytest.raises(Failure):
        loads(data)


def test_request_identity_and_protocol_version_are_exact():
    data = reply("wrong", [{"target": "a", "data": 1}])
    with pytest.raises(Failure):
        protocol.response(data, "request", ["a"])
    wrong_hello = protocol.frame({"version": True, "type": "hello", "protocol": 1})
    with pytest.raises(Failure):
        protocol.response(wrong_hello + protocol.frame({"version": 1, "type": "result", "id": "request",
                            "results": [{"target": "a", "data": 1}]}), "request", ["a"])
