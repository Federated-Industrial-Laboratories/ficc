# SPDX-License-Identifier: Apache-2.0
"""Exchange bounded decision batches over a private Unix socket."""

import http.client
import io
import json
import os
import re
import socket
import stat
import threading
import time
from pathlib import Path
from typing import cast

from .process import START_SECONDS, Service

MAX_REQUEST = 256 * 1024
MAX_RESPONSE = 64 * 1024
MAX_BATCH = 64
EVALUATE_SECONDS = 2.0
REASON = re.compile(r"[a-z][a-z0-9_.-]{0,79}")


def pairs(items: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in items:
        if key in value:
            raise ValueError("The policy response has repeated fields.")
        value[key] = item
    return value


def encode(envelope: dict) -> bytes:
    if (not isinstance(envelope, dict) or set(envelope) != {"version", "revision", "requests"}
            or type(envelope["version"]) is not int or envelope["version"] != 1
            or type(envelope["revision"]) is not int or envelope["revision"] < 0
            or not isinstance(envelope["requests"], list)
            or not 1 <= len(envelope["requests"]) <= MAX_BATCH):
        raise ValueError("The policy request envelope is invalid.")
    identifiers = set()
    for request in envelope["requests"]:
        if (not isinstance(request, dict) or set(request) != {"id", "action", "authority", "labels"}
                or not isinstance(request["id"], str) or not 0 < len(request["id"]) <= 128
                or request["id"] in identifiers or not isinstance(request["action"], str)
                or not 0 < len(request["action"]) <= 128
                or not isinstance(request["authority"], dict) or not isinstance(request["labels"], dict)):
            raise ValueError("The policy request batch is invalid.")
        identifiers.add(request["id"])
    data = json.dumps({"input": envelope}, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_REQUEST:
        raise ValueError("The policy request exceeds its size limit.")
    return data


def decode(data: bytes, envelope: dict) -> list[dict]:
    value = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(value, dict) or set(value) != {"result"} or not isinstance(value["result"], list):
        raise ValueError("The policy result is undefined or invalid.")
    result = value["result"]
    if len(result) != len(envelope["requests"]):
        raise ValueError("The policy result count is invalid.")
    for item, request in zip(result, envelope["requests"], strict=True):
        if (not isinstance(item, dict) or set(item) != {"id", "allow", "reason"}
                or item["id"] != request["id"] or type(item["allow"]) is not bool
                or not isinstance(item["reason"], str) or not REASON.fullmatch(item["reason"])):
            raise ValueError("The policy decision is invalid.")
    return result


class Wire(io.RawIOBase):
    def __init__(self, connection: socket.socket, deadline: float):
        self.connection, self.deadline = connection, deadline
        self.received = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.connection.settimeout(remaining)
        size = self.connection.recv_into(buffer)
        self.received += size
        if self.received > MAX_RESPONSE + 16384:
            raise ValueError("The policy response exceeds its wire limit.")
        return size

    def makefile(self, mode: str) -> io.BufferedReader:
        return io.BufferedReader(self)


def exchange(path: Path, data: bytes) -> bytes:
    deadline = time.monotonic() + EVALUATE_SECONDS
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(EVALUATE_SECONDS)
        connection.connect(str(path))
        headers = ("POST /v1/data/ficc/decisions HTTP/1.1\r\nHost: localhost\r\n"
                   "Content-Type: application/json\r\nConnection: close\r\n"
                   f"Content-Length: {len(data)}\r\n\r\n").encode("ascii")
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.sendall(headers + data)
        with http.client.HTTPResponse(cast(socket.socket, Wire(connection, deadline))) as response:
            response.begin()
            if response.status != 200 or response.getheader("Content-Encoding") is not None:
                raise ValueError("The policy evaluator returned an error.")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE):
                raise ValueError("The policy response exceeds its size limit.")
            received = response.read(MAX_RESPONSE + 1)
            if len(received) > MAX_RESPONSE:
                raise ValueError("The policy response exceeds its size limit.")
            return received


class Runner:
    def __init__(self, source: Path, run: Path):
        self.socket = run / "work" / "opa.sock"
        self.lock = threading.Lock()
        self.service = Service(source, run, ["run", "--server", "--bundle", "/bundle.tar.gz",
                               "--addr", "unix:///run/opa.sock", "--unix-socket-perm", "0600",
                               "--skip-version-check", "--log-level", "error",
                               "--shutdown-grace-period", "0"], finite=False)
        try:
            self.service.admit()
            deadline = time.monotonic() + START_SECONDS
            while not self.socket.exists():
                self.service.healthy()
                if time.monotonic() >= deadline:
                    raise ValueError("The policy evaluator did not start.")
                time.sleep(0.02)
            self.check_socket()
            self.service.check()
        except BaseException:
            self.service.close()
            raise

    def check_socket(self) -> None:
        value = self.socket.lstat()
        if (not stat.S_ISSOCK(value.st_mode) or value.st_uid != os.getuid()
                or stat.S_IMODE(value.st_mode) != 0o600):
            raise ValueError("The policy socket is unsafe.")

    def evaluate(self, envelope: dict) -> list[dict]:
        if not self.lock.acquire(timeout=EVALUATE_SECONDS):
            raise ValueError("The policy evaluator is busy.")
        try:
            try:
                data = encode(envelope)
            except (TypeError, RecursionError):
                raise ValueError("The policy request envelope is invalid.") from None
            try:
                self.service.check()
                self.check_socket()
                result = decode(exchange(self.socket, data), envelope)
                self.service.check()
                return result
            except (ValueError, OSError, http.client.HTTPException, TypeError, RecursionError):
                self.service.close()
                raise ValueError("The policy decision is unavailable or invalid.") from None
            except BaseException:
                self.service.close()
                raise
        finally:
            self.lock.release()

    def close(self) -> None:
        if not self.lock.acquire(timeout=15):
            raise ValueError("The policy evaluator is busy.")
        try:
            try:
                self.service.close()
            except (ValueError, OSError):
                raise ValueError("The policy service stop could not be confirmed.") from None
        finally:
            self.lock.release()
