# SPDX-License-Identifier: Apache-2.0
"""Exchange bounded metadata and binary file chunks over the pinned helper channel."""

import asyncio
import json

from ficc_node.file_access import CHUNK, FileError
from ficc_node.files import dispatch

from .errors import Failure
from .file_worker import owned
from .ssh import PROBE, transport_failure


class FileTransport:
    def __init__(self, service):
        self.service = service
        self.workers = asyncio.Semaphore(4)
        self.endpoints: dict[str, asyncio.Semaphore] = {}
        self.pending = 0

    async def call(self, root, request, data=b"", check=None, timeout=15):
        request = {**request, "root": root, "version": "3", "data_length": len(data),
                   "controller_id": self.service.store.get_setting("controller_id", None)}
        raw = json.dumps(request, allow_nan=False, separators=(",", ":")).encode() + b"\n"
        if len(raw) > 65536 or len(data) > CHUNK:
            raise Failure("request_limit", "The file request exceeds the limit.", 413)
        endpoint = root.get("node_id") or "local"
        semaphore = self.endpoints.setdefault(endpoint, asyncio.Semaphore(2))
        if self.pending >= 64:
            raise Failure("capacity", "The file request queue is full.", 429)
        self.pending += 1
        try:
            return await self.exchange(root, request, raw, data, check, timeout, semaphore)
        finally:
            self.pending -= 1

    async def exchange(self, root, request, raw, data, check, timeout, semaphore):
        async with self.workers, semaphore:
            if check:
                check()
            if root.get("node_id") is None:
                try:
                    return await owned(dispatch, request, data, self.service.settings.state_dir / "files", cancellable=True)
                except FileError as exc:
                    raise Failure(exc.code, exc.message, 409) from exc
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    raise Failure("file_unavailable", "The file action could not be completed.", 409) from exc
            node = self.service.store.node(root["node_id"])
            if node.get("helper_version") != "3":
                raise Failure("helper_upgrade_required", "Upgrade the helper before using files.", 409)
            if root.get("fingerprint") and root["fingerprint"] != node["fingerprint"]:
                raise Failure("root_changed", "The registered node identity changed.", 409)
            code, output, stderr = await self.service.ssh.command(node, PROBE, raw + data, check=check, timeout=timeout)
            try:
                line, payload = output.split(b"\n", 1)
                header = json.loads(line)
                if header.get("version") != "3" or type(header.get("data_length")) is not int:
                    raise ValueError()
                if header["data_length"] != len(payload) or len(payload) > CHUNK:
                    raise ValueError()
                if code == 65 and isinstance(header.get("error"), dict):
                    raise Failure(str(header["error"]["code"])[:80], str(header["error"]["message"])[:240], 409)
                if code:
                    raise transport_failure(stderr)
                if not isinstance(header.get("result"), dict):
                    raise ValueError()
                return header["result"], payload
            except (ValueError, KeyError, TypeError):
                if code:
                    raise transport_failure(stderr) from None
                raise Failure("invalid_file_response", "The node returned an invalid file response.", 502) from None
