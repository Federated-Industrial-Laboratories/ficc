# SPDX-License-Identifier: Apache-2.0
"""Preserve validated display order and bounds across grouped deliveries."""

import pytest

from ficc.viewer.wire import instruction
from ficc.viewer_output import MAX_INSTRUCTIONS, MAX_MESSAGE, Output, OutputError


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_batches_preserve_distinct_instructions_and_flush_each_frame(count):
    for index in range(count):
        output = Output()
        packets = [instruction("size", 0, 320 + index, 240 + offset) for offset in range(129)]
        packets.append(instruction("sync", 1000 + index))
        batches = list(output.iter_batches(b"".join(packets)))
        assert batches == [b"".join(packets[:64]), b"".join(packets[64:128]), b"".join(packets[128:])]
        assert all(len(batch) <= MAX_MESSAGE for batch in batches)
        assert output.acknowledge(packets[-1]) == packets[-1]
    assert MAX_INSTRUCTIONS == 64


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_batches_bound_bytes_and_do_not_split_instructions(monkeypatch, count):
    output = Output()
    packets = [instruction("blob", index, "A" * (8192 + index)) for index in range(count)]
    # This isolates delivery framing from PNG validation, covered by the output tests.
    monkeypatch.setattr(output, "iter_feed", lambda data: iter(packets))
    batches = list(output.iter_batches(b""))
    assert b"".join(batches) == b"".join(packets)
    assert all(len(batch) <= MAX_MESSAGE for batch in batches)
    assert all(batch.endswith(b";") for batch in batches)
    assert len(batches) == (1 if count == 1 else 10)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_batches_refuse_invalid_native_tail_and_continue_fragmented_input(count):
    packets = [instruction("size", 0, 320 + index, 240) for index in range(count)]
    raw = b"".join(packets)
    output = Output()
    first = list(output.iter_batches(raw[:-3]))
    last = list(output.iter_batches(raw[-3:]))
    assert b"".join(first + last) == raw
    with pytest.raises(OutputError):
        list(output.iter_batches(instruction("clipboard", 1, "text/plain")))


def test_each_sync_flushes_before_the_next_frame_is_parsed():
    output = Output()
    packets = [instruction("sync", index + 1) for index in range(64)]
    batches = output.iter_batches(b"".join(packets))
    for packet in packets:
        assert next(batches) == packet
        assert len(output.syncs) == 1
        assert output.acknowledge(packet) == packet
    with pytest.raises(StopIteration):
        next(batches)
