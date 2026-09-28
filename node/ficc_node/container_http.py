# SPDX-License-Identifier: Apache-2.0
"""Issue bounded local-socket or verified TLS requests for fixed provider adapters."""

import http.client
import os
import socket
import stat
import struct
from urllib.parse import urlencode

from .container_spec import MAX_MESSAGE, ProviderError, decode, encode


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, uid):
        super().__init__("localhost", timeout=4)
        self.path, self.uid = path, uid

    def connect(self):
        info = os.lstat(self.path)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.uid:
            raise ProviderError("container_socket", "The container socket identity is invalid.")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)
        _, uid, _ = struct.unpack("3i", self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != self.uid:
            self.close()
            raise ProviderError("container_socket", "The container service account changed.")


class HTTP:
    def __init__(self, factory, headers=None):
        self.factory, self.headers = factory, headers or {}

    def request(self, method, path, query=None, body=None, limit=MAX_MESSAGE, content_type="application/json", timeout=4):
        connection = self.factory()
        connection.timeout = timeout
        headers = {"Accept": "application/json", "Connection": "close", **self.headers}
        payload = None if body is None else encode(body)
        if payload is not None:
            headers["Content-Type"] = content_type
        if query:
            path += "?" + urlencode(query)
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            data = response.read(limit + 1)
            status = response.status
            if status not in {200, 201, 204, 304}:
                code = "container_stale" if status in {404, 409, 422} else "container_denied" if status in {401, 403} else "container_provider"
                raise ProviderError(code, f"The container API refused the request (HTTP {status}).")
            return status, data[:limit], len(data) > limit
        except ProviderError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise ProviderError("container_unavailable", "The container API connection failed or timed out.") from exc
        finally:
            connection.close()

    def json(self, method, path, query=None, body=None, content_type="application/json", timeout=4):
        _, data, truncated = self.request(method, path, query, body, content_type=content_type, timeout=timeout)
        if truncated:
            raise ProviderError("container_limit", "The provider response exceeds the byte limit.")
        return decode(data)


def log_text(data, limit):
    value = data[:limit].decode("utf-8", "replace")
    return "".join(char if ord(char) >= 32 or char in "\n\t" else "\ufffd" for char in value)
