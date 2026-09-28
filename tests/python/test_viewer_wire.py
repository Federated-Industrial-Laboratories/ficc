# SPDX-License-Identifier: Apache-2.0
"""Refuse arbitrary viewer messages, excessive dimensions and malformed frames."""

import asyncio

import pytest

from ficc.viewer import wire


@pytest.mark.parametrize("count", [1, 64])
async def test_bounded_frame_batches(count):
    reader = asyncio.StreamReader()
    for index in range(count):
        reader.feed_data(wire.frame(wire.PROVIDER, bytes([index]) * 65536))
    reader.feed_eof()
    for index in range(count):
        assert await wire.read_frame(reader) == (wire.PROVIDER, bytes([index]) * 65536)


@pytest.mark.parametrize("args", [("key", 0xFF1B, 1), ("mouse", 0, 2159, 31),
    ("size", 4096, 2160), ("sync", 1790609000000), ("ack", 1, "OK", 0), ("disconnect",)])
def test_permitted_display_input(args):
    data = wire.instruction(*args)
    assert wire.permitted_input(data) == data


@pytest.mark.parametrize("args", [("clipboard", 1, "text/plain"), ("file", 1, "text/plain", "name"),
    ("blob", 1, "YQ=="), ("connect", "host"), ("size", 4097, 2160), ("size", 1280, 2161),
    ("size", 0, 768), ("mouse", -1, 0, 0), ("key", 10, 2), ("key", 2**32, 1),
    ("ack", 1, "x" * 65, 0), ("sync", 2**53), ("nop", "extra")])
def test_sensitive_and_excessive_instructions_refused(args):
    with pytest.raises(ValueError):
        wire.permitted_input(wire.instruction(*args))


@pytest.mark.parametrize("text", ["", "3.nop", "3.nop;3.nop;", "03.nop;;", "999999.nop;", "x.nop;",
    "3.nop;garbage", "4.nop;", "3.nop,", "3.nop\x00", "1.x," * 129 + "0.;"])
def test_malformed_instructions_refused(text):
    with pytest.raises(ValueError):
        wire.parse(text)


@pytest.mark.parametrize("kind,size", [(0, 1), (6, 1), (1, 0), (1, 65537), (1, 2**32 - 1)])
async def test_wire_headers_rejected_before_payload_allocation(kind, size):
    reader = asyncio.StreamReader()
    reader.feed_data(wire.HEADER.pack(kind, size))
    with pytest.raises(ValueError):
        await wire.read_frame(reader)
