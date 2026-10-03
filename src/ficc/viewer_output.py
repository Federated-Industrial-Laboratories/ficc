# SPDX-License-Identifier: Apache-2.0
"""Validate native display output before it reaches a browser canvas."""

import base64
import codecs
import re
import struct
import time

from .viewer.wire import instruction, number, parse

MAX_IMAGE = 8 * 1024 * 1024
MAX_MESSAGE = 65536
MAX_INSTRUCTIONS = 64


class OutputError(ValueError):
    """Report a fixed display validation failure without provider content."""


class Output:
    def __init__(self):
        self.decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self.buffer = ""
        self.layers = {0: (0, 0)}
        self.streams: dict[int, dict] = {}
        self.syncs: dict[int, int] = {}
        self.last_stamp = 0
        self.started = time.monotonic()
        self.bytes = self.count = self.frame_bytes = self.frame_count = 0
        self.frame_pixels = 0

    def layer(self, value):
        if not re.fullmatch(r"-?[0-9]{1,6}", value):
            raise OutputError("Invalid display layer.")
        index = int(value)
        if index not in self.layers:
            if len(self.layers) >= 8:
                raise OutputError("Display layer limit reached.")
            self.layers[index] = (0, 0)
        return index

    def area(self, layer, x, y, width, height):
        if min(x, y, width, height) < 0 or x + width > 4096 or y + height > 2160:
            raise OutputError("Display area exceeds its limit.")
        old = self.layers[layer]
        self.layers[layer] = max(old[0], x + width), max(old[1], y + height)
        # Canvas backing stores round dimensions up to multiples of 64.
        pixels = sum(((w + 63) // 64 * 64) * ((h + 63) // 64 * 64) for w, h in self.layers.values())
        if pixels > 20 * 1024 * 1024:
            raise OutputError("Display canvas memory limit reached.")

    def image(self, args):
        index, mask, layer, mime, x, y = args
        index = number(index, 65535)
        number(mask, 15)
        layer, x, y = self.layer(layer), number(x, 4095), number(y, 2159)
        if mime != "image/png":
            raise OutputError("Unsupported display image format.")
        if index in self.streams:
            raise OutputError("The display image stream is already open.")
        if len(self.streams) >= 4:
            raise OutputError("The display image stream limit was reached.")
        self.streams[index] = {"args": args, "layer": layer, "x": x, "y": y, "data": bytearray()}

    def complete_image(self, index):
        stream = self.streams.pop(index)
        data = stream["data"]
        if (len(data) < 45 or data[:16] != b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"):
            raise OutputError("Invalid display PNG header.")
        width, height = struct.unpack(">II", data[16:24])
        if not width or not height:
            raise OutputError("Invalid display image dimensions.")
        self.area(stream["layer"], stream["x"], stream["y"], width, height)
        self.frame_pixels += width * height
        if self.frame_pixels > 32 * 1024 * 1024:
            raise OutputError("Display frame pixel limit reached.")
        offset, ended = 8, False
        while offset + 12 <= len(data):
            size = struct.unpack(">I", data[offset:offset + 4])[0]
            kind = bytes(data[offset + 4:offset + 8])
            if kind not in {b"IHDR", b"IDAT", b"IEND", b"PLTE", b"tRNS", b"sRGB", b"gAMA", b"cHRM", b"pHYs", b"bKGD"}:
                raise OutputError("Unsupported display PNG chunk.")
            offset += size + 12
            if offset > len(data) or ended:
                raise OutputError("Invalid display PNG boundary.")
            ended = kind == b"IEND" and size == 0
        if offset != len(data) or not ended:
            raise OutputError("Incomplete display PNG.")
        result = [instruction("img", *stream["args"])]
        for start in range(0, len(data), 8192):
            result.append(instruction("blob", index, base64.b64encode(data[start:start + 8192]).decode("ascii")))
        result.append(instruction("end", index))
        return result

    def accept(self, values):
        op, args = values[0], values[1:]
        counts = {"ready": (1,), "name": (1,), "sync": (1, 2), "size": (3,), "rect": (5,),
                  "cfill": (6,), "copy": (9,), "cursor": (7,), "dispose": (1,), "reset": (1,),
                  "img": (6,), "blob": (2,), "end": (1,), "mouse": (2, 4),
                  "error": (2,), "disconnect": (0,), "nop": (0,)}
        if op not in counts or len(args) not in counts[op]:
            raise OutputError("Unsupported display output instruction.")
        if op in {"ready", "name"}:
            if len(args[0]) > 256:
                raise OutputError("Invalid display metadata.")
            return []
        if op == "error":
            raise OutputError("The native viewer reported a display error.")
        if op == "sync":
            stamp = number(args[0], 2**53 - 1)
            if len(args) == 2:
                number(args[1], 65535)
            if self.streams:
                raise OutputError("The display frame contains unfinished images.")
            if len(self.syncs) >= 3:
                raise OutputError("Display frame acknowledgement limit reached.")
            # Native frame timestamps can repeat during connection setup.
            # Give each browser frame a distinct acknowledgement identity.
            self.last_stamp = max(stamp, self.last_stamp + 1)
            if self.last_stamp > 2**53 - 1:
                raise OutputError("The display frame timestamp exceeds its limit.")
            self.syncs[self.last_stamp] = stamp
            values = [op, str(self.last_stamp), *args[1:]]
            self.frame_count = self.frame_bytes = self.frame_pixels = 0
        elif op == "img":
            self.image(args)
            return []
        elif op in {"blob", "end"}:
            index = number(args[0], 65535)
            if index not in self.streams:
                raise OutputError("Unknown display image stream.")
            if op == "end":
                return self.complete_image(index)
            data = base64.b64decode(args[1], validate=True)
            stream = self.streams[index]["data"]
            if len(stream) + len(data) > MAX_IMAGE:
                raise OutputError("Display image exceeds its limit.")
            stream.extend(data)
            return []
        elif op == "mouse":
            number(args[0], 4095)
            number(args[1], 2159)
            if len(args) == 4:
                number(args[2], 31)
                number(args[3], 2**53 - 1)
        elif op == "size":
            layer = self.layer(args[0])
            self.layers[layer] = (0, 0)
            self.area(layer, 0, 0, number(args[1], 4096), number(args[2], 2160))
        elif op == "rect":
            self.area(self.layer(args[0]), *[number(value, 4096) for value in args[1:]])
        elif op == "cfill":
            number(args[0], 15)
            self.layer(args[1])
            for value in args[2:]:
                number(value, 255)
        elif op == "copy":
            source, target = self.layer(args[0]), self.layer(args[6])
            x, y, width, height = [number(value, 4096) for value in args[1:5]]
            number(args[5], 15)
            self.area(source, x, y, width, height)
            self.area(target, number(args[7], 4096), number(args[8], 2160), width, height)
        elif op == "cursor":
            number(args[0], 255)
            number(args[1], 255)
            self.area(self.layer(args[2]), number(args[3], 4096), number(args[4], 2160),
                      number(args[5], 256), number(args[6], 256))
        elif op in {"dispose", "reset"}:
            layer = self.layer(args[0])
            if op == "dispose" and layer:
                del self.layers[layer]
        return [instruction(*values)]

    def feed(self, data):
        return list(self.iter_feed(data))

    def iter_batches(self, data):
        """Group complete validated instructions within one bounded delivery."""
        packets: list[bytes] = []
        size = 0
        for packet in self.iter_feed(data):
            if len(packet) > MAX_MESSAGE:
                raise OutputError("Display instruction exceeds its delivery limit.")
            if packets and (size + len(packet) > MAX_MESSAGE or len(packets) == MAX_INSTRUCTIONS):
                yield b"".join(packets)
                packets, size = [], 0
            packets.append(packet)
            size += len(packet)
            if packet.startswith(b"4.sync,"):
                yield b"".join(packets)
                packets, size = [], 0
        if packets:
            yield b"".join(packets)

    def iter_feed(self, data):
        now = time.monotonic()
        if now - self.started >= 1:
            self.started, self.bytes, self.count = now, 0, 0
        self.bytes += len(data)
        self.frame_bytes += len(data)
        if self.bytes > 16 * 1024 * 1024 or self.frame_bytes > 16 * 1024 * 1024:
            raise OutputError("Display output exceeds its byte limit.")
        self.buffer += self.decoder.decode(data)
        if len(self.buffer) > 131072:
            raise OutputError("Display instruction exceeds its buffer limit.")
        while self.buffer:
            position, elements = 0, 0
            while True:
                end = self.buffer.find(".", position, position + 7)
                if end < 0:
                    if len(self.buffer) - position >= 7:
                        raise OutputError("Invalid display element prefix.")
                    return
                size = number(self.buffer[position:end], 65536)
                end += size + 1
                if end >= len(self.buffer):
                    return
                delimiter = self.buffer[end]
                position = end + 1
                elements += 1
                if elements > 16 or position > 65536 or delimiter not in {",", ";"}:
                    raise OutputError("Invalid display element boundary.")
                if delimiter == ";":
                    break
            values = parse(self.buffer[:position], 65536)
            self.buffer = self.buffer[position:]
            self.count += 1
            self.frame_count += 1
            if self.count > 8192 or self.frame_count > 32768:
                raise OutputError("Display output exceeds its instruction limit.")
            yield from self.accept(values)

    def acknowledge(self, data):
        values = parse(data.decode("ascii"))
        if values[0] == "sync":
            stamp = number(values[1], 2**53 - 1)
            if stamp not in self.syncs:
                raise OutputError("Invalid display frame acknowledgement.")
            return instruction("sync", self.syncs.pop(stamp), *values[2:])
        return data
