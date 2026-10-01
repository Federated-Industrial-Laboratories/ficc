# SPDX-License-Identifier: Apache-2.0
"""Refuse native display resource abuse before browser decoding."""

import base64
import struct
import zlib

import pytest

from ficc.viewer.wire import instruction
from ficc.viewer_output import Output


def png(width=1, height=1, extra=None):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    result = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    if extra:
        result += chunk(extra, b"12345678")
    return result + chunk(b"IDAT", zlib.compress(b"\0\xff\0\0")) + chunk(b"IEND", b"")


def image(data):
    return (instruction("img", 1, 14, 0, "image/png", 0, 0)
            + instruction("blob", 1, base64.b64encode(data).decode()) + instruction("end", 1))


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("chunk", [1, 7, 32768])
def test_bounded_frames_and_fragmented_png(count, chunk):
    output = Output()
    for index in range(1, count + 1):
        packet = instruction("size", 0, 1024, 768) + image(png()) + instruction("sync", index)
        result = []
        for start in range(0, len(packet), chunk):
            result.extend(output.feed(packet[start:start + chunk]))
        assert b"".join(result) == packet
        output.acknowledge(instruction("sync", index))
    assert not output.streams and not output.syncs and not output.buffer


@pytest.mark.parametrize("values", [
    ("clipboard", 1, "text/plain"), ("file", 1, "text/plain", "x"), ("audio", 1, "audio/ogg"),
    ("video", 1, 0, "video/mp4"), ("pipe", 1, "text/plain", "x"), ("nest", 1, "4.nop;"),
    ("size", 0, 4097, 1), ("size", 0, 1, 2161), ("size", 0, "NaN", 10),
    ("rect", 0, 4095, 0, 2, 1), ("cursor", 0, 0, 0, 0, 0, 257, 1),
    ("img", 1, 14, 0, "image/svg+xml", 0, 0), ("blob", 1, "eA=="),
    ("sync", "-1"), ("cfill", 14, 0, 256, 0, 0, 255),
])
def test_native_output_capabilities_and_geometry(values):
    with pytest.raises(ValueError):
        Output().feed(instruction(*values))


@pytest.mark.parametrize("data", [png(100000, 100000), png(extra=b"acTL"), b"<svg/>", png()[:-1]])
def test_decode_and_animation_bombs_never_reach_browser(data):
    output = Output()
    with pytest.raises(ValueError):
        output.feed(image(data))


def test_canvas_frames_and_parser_memory_are_bounded():
    output = Output()
    with pytest.raises(ValueError):
        for index in range(9):
            output.feed(instruction("size", index, 1, 1))
    output = Output()
    with pytest.raises(ValueError):
        for index in range(4):
            output.feed(instruction("size", index, 4096, 2160))
    output = Output()
    with pytest.raises(ValueError):
        for index in range(4):
            output.feed(instruction("sync", index))
    with pytest.raises(ValueError):
        Output().feed(b"9999999.")
    with pytest.raises(ValueError):
        Output().acknowledge(instruction("sync", 1))


def test_repeated_native_timestamps_have_distinct_browser_receipts():
    output = Output()
    assert output.feed(instruction("sync", 100) * 3) == [instruction("sync", value) for value in [100, 101, 102]]
    assert len(output.syncs) == 3
    for value in [100, 101, 102]:
        assert output.acknowledge(instruction("sync", value)) == instruction("sync", 100)
    assert not output.syncs


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("with_state", [False, True])
def test_remote_cursor_position_preserves_bounded_display_metadata(count, with_state):
    output = Output()
    for index in range(count):
        values = ["mouse", index * 37, index * 29]
        if with_state:
            values.extend([index % 32, 1000 + index])
        packet = instruction(*values)
        assert output.feed(packet) == [packet]
    assert output.layers == {0: (0, 0)}
    assert not output.streams and not output.syncs


@pytest.mark.parametrize("values", [
    ("mouse", -1, 0), ("mouse", 4096, 0), ("mouse", 0, 2160),
    ("mouse", "NaN", 0), ("mouse", 0, 0, 0), ("mouse", 0, 0, 32, 0),
    ("mouse", 0, 0, -1, 0), ("mouse", 0, 0, 0, -1),
    ("mouse", 0, 0, 0, 2**53), ("mouse", 0, 0, 0, 0, 0),
])
def test_remote_cursor_cannot_expand_geometry_or_input_fields(values):
    with pytest.raises(ValueError):
        Output().feed(instruction(*values))
