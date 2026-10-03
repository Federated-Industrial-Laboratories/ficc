# SPDX-License-Identifier: Apache-2.0
"""Protect whole-source binding, physical reservation and exact large offsets."""

import hashlib
import os

import pytest
from ficc_node.file_access import CHUNK, regular
from ficc_node.file_manifest import chain_next, chain_seed
from test_files import files_fixture as files_fixture
from test_files import listing
from test_transfers import admitted

from ficc.errors import Failure
from ficc.file_numbers import wire
from ficc.file_schema import TransferPreview


def manifest(data, algorithm):
    hashed = hashlib.sha256(data).hexdigest()
    if algorithm == "sha256-chain-v1":
        value = chain_seed(len(data))
        for offset in range(0, len(data), CHUNK):
            value = chain_next(value, hashlib.sha256(data[offset:offset+CHUNK]).digest())
        hashed = value.hex()
    return {"algorithm": algorithm, "digest": hashed}


@pytest.mark.parametrize("algorithm", ["sha256", "sha256-chain-v1"])
async def test_resumed_upload_refuses_changed_unaccepted_suffix(files_fixture, algorithm):
    service, actor, root, path = files_fixture
    data = b"x" * CHUNK + b"original"
    source = {"name": "bound", "size": len(data), "source_manifest": manifest(data, algorithm)}
    operation, _ = await admitted(service, actor, [source], root, "upload")
    item = operation["items"][0]
    prefix = data[:CHUNK]
    await service.transfers.upload(operation["id"], item["id"], actor, 0, prefix, hashlib.sha256(prefix).hexdigest())
    await service.transfers.change(operation["id"], [item["id"]], actor)
    await service.transfers.change(operation["id"], [item["id"]], actor, resume=True)
    await service.transfers.upload(operation["id"], item["id"], actor, 0, prefix, hashlib.sha256(prefix).hexdigest())
    changed = b"modified"
    await service.transfers.upload(operation["id"], item["id"], actor, CHUNK, changed, hashlib.sha256(changed).hexdigest())
    with pytest.raises(Failure, match="original source digest"):
        await service.transfers.finish(operation["id"], item["id"], actor)
    assert not (path / "bound").exists()
    await service.transfers.change(operation["id"], [item["id"]], actor, discard=True)


async def test_physical_reservation_survives_partial_resume_and_cleanup(files_fixture):
    service, actor, root, path = files_fixture
    data = b"q" * (2 * 1024**2 + 1)
    operation, _ = await admitted(service, actor, [{"name": "reserved", "size": len(data), "source_manifest": manifest(data, "sha256")}], root, "upload")
    item = operation["items"][0]
    await service.transfers.destination(operation, item, "transfer.begin", spec=item["spec"])
    partial = path / (".ficc-transfer-" + item["id"]) / "data"
    assert partial.stat().st_size == 0 and partial.stat().st_blocks * 512 >= len(data)
    await service.transfers.upload(operation["id"], item["id"], actor, 0, data[:CHUNK], hashlib.sha256(data[:CHUNK]).hexdigest())
    await service.transfers.change(operation["id"], [item["id"]], actor)
    await service.transfers.change(operation["id"], [item["id"]], actor, resume=True)
    assert partial.stat().st_blocks * 512 >= len(data)
    await service.transfers.change(operation["id"], [item["id"]], actor, discard=True)
    assert not partial.parent.exists() and not (path / "reserved").exists()


async def test_legacy_resume_refuses_lost_chunk_acknowledgement(files_fixture):
    service, actor, root, _ = files_fixture
    operation, _ = await admitted(service, actor, [{"name": "legacy", "size": CHUNK+1}], root, "upload")
    item = operation["items"][0]
    await service.transfers.destination(operation, item, "transfer.begin", spec=item["spec"])
    data = b"x" * CHUNK
    await service.transfers.destination(operation, item, "transfer.write", data=data, offset=0, sha256=hashlib.sha256(data).hexdigest())
    assert service.transfers.store.get(operation["id"])["items"][0]["offset"] == 0
    with pytest.raises(Failure) as denied:
        await service.transfers.change(operation["id"], [item["id"]], actor, resume=True)
    assert denied.value.code == "source_manifest_required"
    recorded = service.transfers.store.get(operation["id"])["items"][0]
    assert recorded["state"] == "interrupted" and recorded["offset"] == CHUNK
    await service.transfers.change(operation["id"], [item["id"]], actor, discard=True)


async def test_large_source_offsets_and_browser_integer_contract(files_fixture):
    service, actor, root, path = files_fixture
    offset = 17 * 1024**3
    with (path / "sparse").open("wb") as stream:
        stream.seek(offset)
        stream.write(b"tail")
        regular(os.fstat(stream.fileno()))
    entry = (await listing(service, actor, root))["entries"][0]
    _, reference = service.files.resolve(root["id"], entry["entry_id"], actor)
    header, data = await service.files.call(root, {"action": "file.read", "entry": reference, "offset": offset, "limit": 4}, actor)
    assert data == b"tail" and header["next_offset"] == offset + 4
    exact = 2**53 + 1
    request = TransferPreview.model_validate({"kind": "upload", "sources": [{"name": "exact", "size": str(exact)}]})
    assert request.sources[0].size == exact
    assert wire({"size": exact, "offset": offset}) == {"size": str(exact), "offset": offset}
    preview = await service.transfers.preview({"kind": "upload", "sources": [{"name": "large", "size": offset+4}],
        "destination": {"root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"])}}, actor)
    assert preview["items"][0]["size"] == offset + 4
    service.store.set_setting("transfer_limits", {"retained_bytes": None, "free_bytes": 256 * 1024**2})
    assert service.transfers.limits()["retained_bytes"] is None
