# SPDX-License-Identifier: Apache-2.0
"""Bound private viewer frames and permit only display-session input instructions."""

import struct

MAX_FRAME = 65536
HEADER = struct.Struct(">BI")
CONFIG, PROVIDER, DISPLAY, READY, END = range(1, 6)


def frame(kind, data):
    if kind not in {CONFIG, PROVIDER, DISPLAY, READY, END} or not 0 < len(data) <= MAX_FRAME:
        raise ValueError("Invalid viewer frame.")
    return HEADER.pack(kind, len(data)) + data


async def read_frame(reader):
    kind, size = HEADER.unpack(await reader.readexactly(HEADER.size))
    if kind not in {CONFIG, PROVIDER, DISPLAY, READY, END} or not 0 < size <= MAX_FRAME:
        raise ValueError("Invalid viewer frame.")
    return kind, await reader.readexactly(size)


def instruction(*values):
    text = ",".join(str(len(str(value))) + "." + str(value) for value in values) + ";"
    return text.encode("utf-8")


def parse(data, maximum=4096):
    if not isinstance(data, str) or not 0 < len(data) <= maximum:
        raise ValueError("Invalid display instruction size.")
    result: list[str] = []
    position = 0
    while position < len(data):
        end = data.find(".", position, position + 7)
        if end < 0 or not data[position:end].isascii() or not data[position:end].isdigit():
            raise ValueError("Invalid display element length.")
        size = int(data[position:end])
        position = end + 1
        end = position + size
        if end >= len(data) or len(result) >= 128:
            raise ValueError("Invalid display element boundary.")
        result.append(data[position:end])
        separator = data[end]
        position = end + 1
        if separator == ";" and position == len(data):
            return result
        if separator != ",":
            raise ValueError("Invalid display instruction separator.")
    raise ValueError("Incomplete display instruction.")


def number(value, maximum):
    if not value or len(value) > 16 or not value.isascii() or not value.isdigit() or int(value) > maximum:
        raise ValueError("Invalid display input number.")
    return int(value)


def permitted_input(data):
    values = parse(data.decode("ascii"))
    opcode, args = values[0], values[1:]
    if opcode == "key" and len(args) == 2:
        number(args[0], 0xFFFFFFFF)
        number(args[1], 1)
    elif opcode == "mouse" and len(args) in {3, 4}:
        number(args[0], 4095)
        number(args[1], 2159)
        number(args[2], 31)
        if len(args) == 4:
            number(args[3], 2**53 - 1)
    elif opcode == "size" and len(args) == 2:
        if not 64 <= number(args[0], 4096) or not 64 <= number(args[1], 2160):
            raise ValueError("Invalid display dimensions.")
    elif opcode == "sync" and len(args) in {1, 2}:
        for arg in args:
            number(arg, 2**53 - 1)
    elif opcode == "ack" and len(args) == 3:
        number(args[0], 65535)
        number(args[2], 65535)
        if len(args[1]) > 64:
            raise ValueError("Invalid display acknowledgement.")
    elif opcode in {"nop", "disconnect"} and not args:
        pass
    else:
        raise ValueError("The display input instruction is not permitted.")
    return data
