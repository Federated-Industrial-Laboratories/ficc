# SPDX-License-Identifier: Apache-2.0
"""Relay a registered TCP display endpoint without exposing its private settings."""

import asyncio
import ipaddress
import json
import re

from .viewer.configuration import settings


class TCPProviderStream:
    def __init__(self):
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def start(self, connection, check):
        if not isinstance(connection, dict) or set(connection) != {"host", "port", "configuration"}:
            raise ValueError("Invalid registered display connection.")
        host, port = connection["host"], connection["port"]
        if not isinstance(host, str) or not 1 <= len(host) <= 253 or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid registered display address.")
        try:
            ipaddress.ip_address(host)
            if "%" in host:
                raise ValueError("Scoped display addresses are not supported.")
        except ValueError:
            if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host) is None:
                raise ValueError("Invalid registered display address.") from None
        try:
            data = json.dumps(connection["configuration"], ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise ValueError("Invalid private display configuration.") from None
        config = settings(data)
        if config["protocol"] != "rdp":
            raise ValueError("The registered transport requires RDP.")
        check()
        async with asyncio.timeout(8):
            self.reader, self.writer = await asyncio.open_connection(host, port, limit=65536)
        check()
        return data

    async def read(self, size=32768):
        if self.reader is None:
            raise ValueError("The display connection is not open.")
        return await self.reader.read(size)

    async def write(self, data):
        if self.writer is None:
            raise ValueError("The display connection is not open.")
        async with asyncio.timeout(10):
            self.writer.write(data)
            await self.writer.drain()

    async def close(self):
        if self.writer is not None:
            self.writer.close()
            try:
                async with asyncio.timeout(2):
                    await self.writer.wait_closed()
            except (OSError, TimeoutError):
                self.writer.transport.abort()
