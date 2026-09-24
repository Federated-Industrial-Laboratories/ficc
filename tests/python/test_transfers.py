# SPDX-License-Identifier: Apache-2.0
"""Verify bounded copies, upload retries, source changes, and partial cleanup."""

import asyncio
import hashlib
import os

import pytest
from ficc_node.file_access import CHUNK
from test_files import files_fixture as files_fixture
from test_files import listing

from ficc.errors import Failure


async def destination(service, path):
    path.mkdir()
    return await service.files.register(str(path), "Destination")


def location(service, root):
    return {"root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"])}


async def admitted(service, actor, sources, dest=None, kind="copy", overwrite=False):
    body = {"kind": kind, "sources": sources, "destination": location(service, dest) if dest else None,
            "overwrite": overwrite}
    preview = await service.transfers.preview(body, actor)
    result = await service.transfers.submit(preview["preview_id"], "transfer-key-" + preview["preview_id"], actor)
    return result, preview


async def completed(service, operation_id):
    await asyncio.gather(*list(service.transfers.tasks.values()))
    return service.transfers.store.get(operation_id)


@pytest.mark.parametrize("count", [1, 64])
async def test_copy_batch_bytes_and_deduplication(files_fixture, tmp_path, count):
    service, actor, root, path = files_fixture
    target = await destination(service, tmp_path / "destination")
    names = []
    for index in range(count):
        name = f"file-{index:02}-".encode() + b"\xff"
        names.append(name)
        fd = os.open(os.fsencode(path) + b"/" + name, os.O_CREAT | os.O_WRONLY, 0o600)
        os.write(fd, bytes([index]) * (CHUNK + 13 if count == 1 else 13))
        os.close(fd)
    sources = [{"root_id": root["id"], "entry_id": item["entry_id"]} for item in (await listing(service, actor, root))["entries"]]
    op, preview = await admitted(service, actor, sources, target)
    result = await completed(service, op["id"])
    assert result["state"] == "succeeded", result
    assert len(result["items"]) == count
    for index, name in enumerate(names):
        expected = bytes([index]) * (CHUNK + 13 if count == 1 else 13)
        with open(os.fsencode(tmp_path / "destination") + b"/" + name, "rb") as stream:
            assert stream.read() == expected
        assert result["items"][index]["sha256"] == hashlib.sha256(expected).hexdigest()
    again = await service.transfers.submit(preview["preview_id"], op["key"], actor)
    assert again["id"] == op["id"] and len(service.transfers.store.all()) == 1


async def test_upload_chunk_bounds_hash_retry_finish_and_empty(files_fixture, tmp_path):
    service, actor, root, path = files_fixture
    data = b"A" * CHUNK + b"end"
    op, _ = await admitted(service, actor, [{"name": "upload", "size": len(data), "last_modified": 1}], root, "upload")
    item = op["items"][0]
    with pytest.raises(Failure, match="offset"):
        await service.transfers.upload(op["id"], item["id"], actor, CHUNK, b"end", hashlib.sha256(b"end").hexdigest())
    with pytest.raises(Failure, match="digest"):
        await service.transfers.upload(op["id"], item["id"], actor, 0, data[:CHUNK], "0" * 64)
    assert not (path / "upload").exists()
    for offset in (0, 0, CHUNK):
        chunk = data[offset:offset+CHUNK]
        await service.transfers.upload(op["id"], item["id"], actor, offset, chunk, hashlib.sha256(chunk).hexdigest())
    result = await service.transfers.finish(op["id"], item["id"], actor)
    assert result["state"] == "succeeded" and (path / "upload").read_bytes() == data
    assert (await service.transfers.finish(op["id"], item["id"], actor))["state"] == "succeeded"
    empty, _ = await admitted(service, actor, [{"name": "empty", "size": 0}], root, "upload")
    await service.transfers.finish(empty["id"], empty["items"][0]["id"], actor)
    assert (path / "empty").read_bytes() == b""


async def test_interrupted_copy_resume_and_changed_source(files_fixture, tmp_path, monkeypatch):
    service, actor, root, path = files_fixture
    target = await destination(service, tmp_path / "destination")
    data = b"a" * CHUNK + b"b" * CHUNK + b"c"
    (path / "source").write_bytes(data)
    entry = (await listing(service, actor, root))["entries"][0]
    original = service.transfers.destination
    async def disconnect(op, item, action, **values):
        if action == "transfer.write" and values["offset"] == CHUNK:
            raise Failure("unreachable", "Synthetic disconnect.", 502)
        return await original(op, item, action, **values)
    monkeypatch.setattr(service.transfers, "destination", disconnect)
    op, _ = await admitted(service, actor, [{"root_id": root["id"], "entry_id": entry["entry_id"]}], target)
    result = await completed(service, op["id"])
    assert result["state"] == "interrupted" and result["items"][0]["offset"] == CHUNK
    assert not (tmp_path / "destination/source").exists()
    monkeypatch.setattr(service.transfers, "destination", original)
    await service.transfers.change(op["id"], [op["items"][0]["id"]], actor, resume=True)
    assert (await completed(service, op["id"]))["state"] == "succeeded"
    assert (tmp_path / "destination/source").read_bytes() == data
    (path / "second").write_bytes(data)
    entry = next(item for item in (await listing(service, actor, root))["entries"] if item["name"] == "second")
    monkeypatch.setattr(service.transfers, "destination", disconnect)
    op, _ = await admitted(service, actor, [{"root_id": root["id"], "entry_id": entry["entry_id"]}], target)
    await completed(service, op["id"])
    (path / "second").write_bytes(b"changed")
    monkeypatch.setattr(service.transfers, "destination", original)
    await service.transfers.change(op["id"], [op["items"][0]["id"]], actor, resume=True)
    assert (await completed(service, op["id"]))["state"] == "interrupted"
    assert not (tmp_path / "destination/second").exists()
    await service.transfers.change(op["id"], [op["items"][0]["id"]], actor, discard=True)
    assert service.transfers.store.get(op["id"])["state"] == "cancelled"


async def test_overwrite_conflict_and_revoked_dispatch(files_fixture, tmp_path, monkeypatch):
    service, actor, root, path = files_fixture
    target = await destination(service, tmp_path / "destination")
    (path / "same").write_bytes(b"new")
    (tmp_path / "destination/same").write_bytes(b"original")
    entry = (await listing(service, actor, root))["entries"][0]
    sources = [{"root_id": root["id"], "entry_id": entry["entry_id"]}]
    with pytest.raises(Failure, match="replacement"):
        await admitted(service, actor, sources, target)
    op, _ = await admitted(service, actor, sources, target, overwrite=True)
    assert (await completed(service, op["id"]))["state"] == "succeeded"
    assert (tmp_path / "destination/same").read_bytes() == b"new"
    _, restricted = service.auth.issue("token", scopes=["files:read", "files:write"], root_ids=[root["id"]])
    with pytest.raises(Failure):
        await admitted(service, restricted.id, sources, target)


async def test_download_spool_and_partial_tamper(files_fixture):
    service, actor, root, path = files_fixture
    (path / "result").write_bytes(b"verified result")
    entry = (await listing(service, actor, root))["entries"][0]
    op, _ = await admitted(service, actor, [{"root_id": root["id"], "entry_id": entry["entry_id"]}], kind="download")
    assert (await completed(service, op["id"]))["state"] == "succeeded"
    assert (service.settings.state_dir / "downloads" / op["items"][0]["id"]).read_bytes() == b"verified result"
    with pytest.raises(Failure, match="retained"):
        service.files.unregister(root["id"])
    await service.transfers.change(op["id"], [op["items"][0]["id"]], actor, discard=True)
    assert not service.transfers.active(root_id=root["id"])
    assert not (service.settings.state_dir / "downloads" / op["items"][0]["id"]).exists()
    assert (path / "result").read_bytes() == b"verified result"
    op, _ = await admitted(service, actor, [{"name": "partial", "size": CHUNK+1}], root, "upload")
    item = op["items"][0]
    chunk = b"x" * CHUNK
    await service.transfers.upload(op["id"], item["id"], actor, 0, chunk, hashlib.sha256(chunk).hexdigest())
    partial = path / (".ficc-transfer-" + item["id"]) / "data"
    with partial.open("r+b") as stream:
        stream.write(b"corrupt")
    with pytest.raises(Failure, match="verification"):
        await service.transfers.change(op["id"], [item["id"]], actor, resume=True)
