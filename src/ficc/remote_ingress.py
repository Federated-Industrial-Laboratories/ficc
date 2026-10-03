# SPDX-License-Identifier: Apache-2.0
"""Authenticate private gateway traffic and bound remote request admission."""

import ipaddress
import re
import secrets
import time

from starlette.responses import JSONResponse


class RemoteIngress:
    def __init__(self, app, settings):
        self.app, self.settings = app, settings
        self.clients: dict[str, dict] = {}
        self.global_bucket = {"tokens": 2048.0, "at": time.monotonic()}
        self.login_bucket = {"tokens": 128.0, "at": time.monotonic()}
        self.swept = time.monotonic()

    @staticmethod
    def admit(bucket, rate, capacity, now):
        bucket["tokens"] = min(capacity, bucket["tokens"] + max(0, now - bucket["at"]) * rate)
        bucket["at"] = now
        if bucket["tokens"] < 1:
            return False
        bucket["tokens"] -= 1
        return True

    def check(self, scope):
        headers = scope.get("headers", [])
        if sum(len(key) + len(value) for key, value in headers) > 32768:
            return "request_limit", 431
        gateway = [value for key, value in headers if key == b"x-ficc-gateway"]
        remote = self.settings.remote
        node_path = scope.get("path", "").startswith("/api/v1/node-channel/")
        node_gateway = [value for key, value in headers if key == b"x-ficc-node-gateway"]
        node_fingerprint = [value for key, value in headers if key == b"x-ficc-node-fingerprint"]
        if node_path:
            nodes = self.settings.contributors
            if (nodes is None or gateway or len(node_gateway) != 1 or len(node_fingerprint) != 1
                    or not secrets.compare_digest(node_gateway[0], nodes.secret.encode("ascii"))
                    or not re.fullmatch(rb"[0-9a-f]{64}", node_fingerprint[0])
                    or scope.get("query_string") or any(key in {b"origin", b"authorization", b"cookie"} for key, _ in headers)):
                return "node_gateway_required", 403
            scope.setdefault("state", {})["ficc_node_fingerprint"] = node_fingerprint[0].decode("ascii")
        elif (node_gateway or node_fingerprint or len(gateway) != 1
              or not secrets.compare_digest(gateway[0], remote.secret.encode("ascii"))):
            return "gateway_required", 403
        addresses = [value for key, value in headers if key == b"x-ficc-client-ip"]
        try:
            if len(addresses) != 1:
                raise ValueError("Invalid client address")
            address = str(ipaddress.ip_address(addresses[0].decode("ascii")))
        except (ValueError, UnicodeError):
            return "gateway_required", 403
        if len(scope.get("raw_path", b"")) + len(scope.get("query_string", b"")) > 8192:
            return "request_limit", 414
        now = time.monotonic()
        if now - self.swept > 30:
            self.clients = {key: value for key, value in self.clients.items() if now - value["at"] < 120}
            self.swept = now
        if address not in self.clients:
            if len(self.clients) >= 4096:
                return "capacity", 429
            self.clients[address] = {"tokens": 240.0, "at": now, "login": {"tokens": 16.0, "at": now}}
        current = self.clients[address]
        if (not self.admit(self.global_bucket, 1024, 2048, now)
                or not self.admit(current, 120, 240, now)):
            return "capacity", 429
        if scope.get("path") in {"/auth/start", "/auth/callback"}:
            if (not self.admit(self.login_bucket, 4, 128, now)
                    or not self.admit(current["login"], 2, 16, now)):
                return "capacity", 429
        scope["scheme"] = "wss" if scope["type"] == "websocket" else "https"
        scope["client"] = (address, 0)
        scope["headers"] = [(key, value) for key, value in headers if key not in
                             {b"x-ficc-gateway", b"x-ficc-client-ip", b"forwarded"}
                             and not key.startswith((b"x-forwarded-", b"x-ficc-node-"))]
        return None

    async def __call__(self, scope, receive, send):
        if self.settings.remote is not None and scope["type"] in {"http", "websocket"}:
            error = self.check(scope)
            if error:
                code, status = error
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 4403 if status != 429 else 4429})
                else:
                    response = JSONResponse({"error": {"code": code, "message": "Remote request admission failed."}},
                                            status_code=status, headers={"Cache-Control": "no-store", "Retry-After": "1"})
                    await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
