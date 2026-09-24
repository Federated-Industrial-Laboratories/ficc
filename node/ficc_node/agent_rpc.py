# SPDX-License-Identifier: Apache-2.0
"""Use bounded RFC 6455 frames on an owned Codex Unix socket."""

import base64
import hashlib
import json
import os
import socket
import struct
import time

LIMIT = 1024 * 1024


class RPCError(ValueError):
    def __init__(self, method, error):
        self.code = error.get("code") if isinstance(error, dict) else None
        super().__init__("The runtime refused " + method + ": " + str(error)[:200])


class RPC:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        self.socket.connect(str(path))
        self.sequence = 0
        self.events = []
        key = base64.b64encode(os.urandom(16)).decode()
        self.socket.sendall(("GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                             "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                             f"Sec-WebSocket-Key: {key}\r\n\r\n").encode())
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            header.extend(self.exact(1))
            if len(header) > 8192:
                raise ValueError("The runtime handshake exceeds capacity.")
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        if not header.startswith(b"HTTP/1.1 101 ") or b"sec-websocket-accept: " + accept.lower() not in bytes(header).lower():
            raise ValueError("The runtime WebSocket handshake is invalid.")
        self.call("initialize", {"clientInfo": {"name": "ficc", "version": "0.1"},
                                 "capabilities": {"experimentalApi": True}})
        self.send({"method": "initialized", "params": {}})

    def exact(self, size):
        data = bytearray()
        while len(data) < size:
            part = self.socket.recv(size - len(data))
            if not part:
                raise ValueError("The runtime connection closed.")
            data.extend(part)
        return bytes(data)

    def frame(self, opcode, payload):
        if len(payload) > LIMIT:
            raise ValueError("The runtime request exceeds capacity.")
        mask = os.urandom(4)
        size = len(payload)
        length = bytes([size | 128]) if size < 126 else (b"\xfe" + struct.pack("!H", size) if size < 65536 else b"\xff" + struct.pack("!Q", size))
        encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.socket.sendall(bytes([128 | opcode]) + length + mask + encoded)

    def send(self, value):
        self.frame(1, json.dumps(value, allow_nan=False).encode())

    def receive(self):
        data = bytearray()
        started = False
        for _ in range(128):
            first, second = self.exact(2)
            if first & 112 or second & 128:
                raise ValueError("The runtime frame flags are invalid.")
            size = second & 127
            if size == 126:
                size = struct.unpack("!H", self.exact(2))[0]
            elif size == 127:
                size = struct.unpack("!Q", self.exact(8))[0]
            if size > LIMIT or len(data) + size > LIMIT:
                raise ValueError("The runtime response exceeds capacity.")
            payload, opcode = self.exact(size), first & 15
            if opcode == 8:
                raise ValueError("The runtime connection closed.")
            if opcode == 9:
                self.frame(10, payload)
                continue
            if opcode == 10:
                continue
            if opcode not in ({0} if started else {1}):
                raise ValueError("The runtime frame sequence is invalid.")
            started = True
            data.extend(payload)
            if first & 128:
                return json.loads(data)
        raise ValueError("The runtime response frame count exceeds capacity.")

    def call(self, method, params):
        self.sequence += 1
        self.send({"id": self.sequence, "method": method, "params": params})
        deadline = time.monotonic() + 10
        for _ in range(256):
            self.socket.settimeout(max(0.01, deadline - time.monotonic()))
            value = self.receive()
            if value.get("id") == self.sequence and ("result" in value or "error" in value):
                if "error" in value:
                    raise RPCError(method, value["error"])
                return value["result"]
            # Approval requests are never answered by this bridge.
            if "method" in value and "id" not in value:
                self.events.append(value)
                self.events = self.events[-128:]
        raise ValueError("The runtime notification limit was reached.")

    def close(self):
        self.socket.close()
