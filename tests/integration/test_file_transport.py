# SPDX-License-Identifier: Apache-2.0
"""Verify packaged binary file operations through an isolated OpenSSH server."""

import asyncio
import hashlib
import os

import pytest
from ficc_node.file_access import CHUNK
from test_ssh import ssh_fixture as ssh_fixture

from ficc.errors import Failure
from ficc.service import Service


async def test_real_file_upload_copy_download_and_grants(ssh_fixture):
    transport, home, temporary = ssh_fixture
    service = Service(transport.settings)
    service.ssh = transport
    _, actor = service.auth.issue("token")
    preview = await transport.preview("fixture-node", "Test machine")
    await transport.install(preview)
    node = {**preview, "id": "a" * 32, "helper_version": "3"}
    service.store.save_node(node)
    local_path, remote_path, other_path = temporary / "local", home / "files", home / "other"
    for path in (local_path, remote_path, other_path):
        path.mkdir()
    try:
        local = await service.files.register(str(local_path), "Controller")
        remote = await service.files.register(str(remote_path), "Node", node["id"])
        other = await service.files.register(str(other_path), "Node destination", node["id"])
        def location(root):
            return {"root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"])}
        for index in range(64):
            (remote_path / f"entry-{index:02}").write_bytes(bytes([index]))
        listing = await service.files.listing({**location(remote), "limit": 200}, actor.id)
        assert len(listing["entries"]) == 64 and listing["next_cursor"] is None
        binary = bytes([0, 255, 10]) * (CHUNK // 3 + 19)
        transfer_preview = await service.transfers.preview({"kind": "upload", "sources": [
            {"name": "binary", "size": len(binary)}], "destination": location(remote), "overwrite": False}, actor.id)
        upload = await service.transfers.submit(transfer_preview["preview_id"], "real-upload-file-key", actor.id)
        item = upload["items"][0]
        for offset in range(0, len(binary), CHUNK):
            chunk = binary[offset:offset + CHUNK]
            await service.transfers.upload(upload["id"], item["id"], actor.id, offset, chunk, hashlib.sha256(chunk).hexdigest())
        await service.transfers.finish(upload["id"], item["id"], actor.id)
        assert (remote_path / "binary").read_bytes() == binary
        listing = await service.files.listing({**location(remote), "limit": 200}, actor.id)
        entry = next(value for value in listing["entries"] if value["name"] == "binary")
        source = {"root_id": remote["id"], "entry_id": entry["entry_id"]}
        for index, destination in enumerate((other, local)):
            transfer_preview = await service.transfers.preview({"kind": "copy", "sources": [source],
                "destination": location(destination), "overwrite": False}, actor.id)
            copy = await service.transfers.submit(transfer_preview["preview_id"], f"real-copy-file-key-{index}", actor.id)
            await asyncio.gather(*list(service.transfers.tasks.values()))
            assert service.transfers.store.get(copy["id"])["state"] == "succeeded"
        assert (other_path / "binary").read_bytes() == (local_path / "binary").read_bytes() == binary
        _, restricted = service.auth.issue("token", scopes=["files:read"], root_ids=[local["id"]])
        with pytest.raises(Failure):
            await service.files.listing({**location(remote), "limit": 100}, restricted.id)
        (remote_path / "symlink").symlink_to(local_path)
        with pytest.raises(Failure):
            await service.files.register(str(remote_path / "symlink"), "Refused", node["id"])
        assert not any(name.startswith(".ficc-transfer-") for name in os.listdir(remote_path))
    finally:
        await service.transfers.close()
        await service.files.close()
        service.store.close()
