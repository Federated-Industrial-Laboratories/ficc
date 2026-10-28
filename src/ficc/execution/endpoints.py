# SPDX-License-Identifier: Apache-2.0
"""Fenced HTTP streams through owned Unix sockets with bounded backpressure."""
import base64
import http.client
import queue
import socket
import stat
import struct
import threading
import time
from pathlib import Path

from .ledger import Conflict


class Connection(http.client.HTTPConnection):
    def __init__(self, path, ctx, timeout):
        super().__init__("localhost", timeout=5)
        self.path, self.ctx, self.deadline_timeout = path, ctx, timeout

    def connect(self):
        before = self.path.lstat()
        if not stat.S_ISSOCK(before.st_mode) or before.st_uid != self.ctx["slot"]["uid"]:
            raise Conflict("endpoint_identity")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.deadline_timeout)
            sock.connect(str(self.path))
            pid, uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            after = self.path.lstat()
            group = next((line for line in (Path("/proc") / str(pid) / "cgroup").read_text().splitlines() if line.startswith("0::")), "")
            if (uid != before.st_uid or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                    or not group.startswith("0::" + self.ctx["cgroup"] + "/")):
                raise Conflict("endpoint_identity")
            self.sock = sock
        except BaseException:
            sock.close()
            raise


class Stream:
    def __init__(self, asked, ctx, check):
        self.asked, self.check, self.ctx = asked, check, ctx
        self.queue: queue.Queue[bytes] = queue.Queue(maxsize=4)
        self.cancelled = threading.Event()
        self.connection = Connection(Path(ctx["directory"]) / "runtime/work" / ctx["plan"]["job"]["endpoint"]["socket"], ctx, asked.deadline_seconds)
        self.status, self.error, self.done = 0, None, False
        self.deadline = time.monotonic() + asked.deadline_seconds
        self.last_read = time.monotonic()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def active(self):
        if self.cancelled.is_set() or time.monotonic() > self.deadline or time.monotonic() - self.last_read > 15:
            raise Conflict("endpoint_cancelled")
        self.check()

    def run(self):
        try:
            self.active()
            if self.asked.input_object is not None:
                item = next(value for value in self.ctx["plan"]["job"]["inputs"] if value["id"] == self.asked.input_object)
                self.connection.putrequest("POST", self.asked.path)
                self.connection.putheader("Content-Type", "application/octet-stream")
                self.connection.putheader("Content-Length", str(item["bytes"]))
                self.connection.putheader("Connection", "close")
                self.connection.endheaders()
                path = Path(self.ctx["directory"]) / "inputs" / item["name"]
                import os
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size != item["bytes"] or info.st_mode & 0o022:
                        raise Conflict("endpoint_input_identity")
                    while data := os.read(fd, 65536):
                        self.active()
                        self.connection.send(data)
                finally:
                    os.close(fd)
            else:
                self.connection.request(self.asked.method, self.asked.path, body=self.asked.body.encode() or None,
                                        headers={"Content-Type": "application/json", "Accept-Encoding": "identity", "Connection": "close"})
            response = self.connection.getresponse()
            self.status = response.status
            while True:
                self.active()
                data = response.read1(65536)
                if not data:
                    break
                while True:
                    self.active()
                    try:
                        self.queue.put(data, timeout=0.1)
                        break
                    except queue.Full:
                        continue
        except Exception:
            self.error = "endpoint_unavailable"
        finally:
            self.connection.close()
            self.done = True

    def cancel(self):
        self.cancelled.set()
        if self.connection.sock:
            try:
                self.connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.connection.close()

    def read(self):
        self.last_read = time.monotonic()
        try:
            data = self.queue.get_nowait()
        except queue.Empty:
            data = b""
        return {"stream_id": self.asked.stream_id, "status": self.status, "data": base64.b64encode(data).decode(),
                "eof": self.done and self.queue.empty(), "error": self.error}


class Endpoints:
    def __init__(self, supervisor):
        self.supervisor = supervisor
        self.streams = {}
        self.lock = threading.RLock()

    def exchange(self, asked):
        with self.lock:
            # Reap abandoned streams without relying on controller cleanup.
            for key, stream in list(self.streams.items()):
                if time.monotonic() - stream.last_read > 15:
                    stream.cancel()
                if stream.cancelled.is_set() and not stream.thread.is_alive():
                    del self.streams[key]
            key = (asked.attempt_id, asked.stream_id)
            stream = self.streams.get(key)
            if asked.operation == "cancel":
                if stream:
                    stream.cancel()
                return {"stream_id": asked.stream_id, "status": 0, "data": "", "eof": True}
            value = self.supervisor.check(asked)
            endpoint = value["plan"]["job"].get("endpoint")
            blob = next((item for item in value["plan"]["job"]["inputs"] if item["id"] == asked.input_object), None)
            permitted = endpoint and (asked.path in endpoint["paths"] and asked.input_object is None or
                "/api/blobs" in endpoint["paths"] and blob is not None and asked.path == "/api/blobs/" + blob["digest"] and asked.method == "POST")
            if value["state"] != "running" or not permitted:
                raise Conflict("endpoint_not_ready")
            if asked.operation == "open":
                if stream is not None:
                    raise Conflict("endpoint_not_replayed")
                if len(self.streams) >= 64 or sum(k[0] == asked.attempt_id for k in self.streams) >= endpoint["concurrency"]:
                    raise Conflict("endpoint_capacity")
                stream = Stream(asked, self.supervisor.ctx(value), lambda: self.supervisor.check(asked))
                self.streams[key] = stream
            elif stream is None:
                raise Conflict("endpoint_stream_unknown")
            if (stream.asked.generation, stream.asked.plan_digest) != (asked.generation, asked.plan_digest):
                raise Conflict("endpoint_generation")
            result = stream.read()
            if result["eof"]:
                del self.streams[key]
            return result

    def close(self):
        for stream in self.streams.values():
            stream.cancel()
        for stream in self.streams.values():
            stream.thread.join(timeout=1)
