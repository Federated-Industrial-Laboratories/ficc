# SPDX-License-Identifier: Apache-2.0
"""Verify preparation recovery and download ownership across response boundaries."""

import asyncio
import errno
import hashlib
import os
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from ficc_node import file_transfer
from test_files import files_fixture as files_fixture
from test_files import listing
from test_transfers import admitted, completed

from ficc.errors import Failure
from ficc.transfer_routes import install


@pytest.mark.parametrize("count", [1, 64])
async def test_download_disconnect_before_body_closes_spool(files_fixture, count):
    service, actor, root, path = files_fixture
    (path / "source").write_bytes(b"verified download")
    entry = (await listing(service, actor, root))["entries"][0]
    operation, _ = await admitted(service, actor, [{"root_id": root["id"], "entry_id": entry["entry_id"]}], kind="download")
    assert (await completed(service, operation["id"]))["state"] == "succeeded"
    item = operation["items"][0]
    app = FastAPI()
    install(app, service, lambda request: SimpleNamespace(id=actor))
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", "").endswith("/content"))
    for _ in range(count):
        response = await endpoint(operation["id"], item["id"], None)
        fd = response.fd
        assert os.fstat(fd).st_size == len(b"verified download")
        async def send(message):
            assert message["type"] == "http.response.start"
            await asyncio.sleep(0.01)
        async def receive():
            return {"type": "http.disconnect"}
        await response({"type": "http", "asgi": {"spec_version": "2.3"}}, receive, send)
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("recovery", ["resume", "discard"])
@pytest.mark.parametrize("boundary", ["mkdir", "parent-sync", "data-create", "data-sync",
                                      "chunks-create", "chunks-sync", "stage-sync", "ready-save"])
async def test_preparation_failure_recovers_without_losing_destination(files_fixture, monkeypatch, boundary, recovery):
    service, actor, root, path = files_fixture
    (path / "target").write_bytes(b"original")
    inode = (path / "target").stat().st_ino
    operation, _ = await admitted(service, actor, [{"name": "target", "size": 1}], root, "upload", overwrite=True)
    item = operation["items"][0]
    stage = path / (".ficc-transfer-" + item["id"])
    originals = {name: getattr(os, name) for name in ("mkdir", "open", "fsync")}
    original_save = file_transfer.save
    hit = []
    def fail(point):
        if boundary == point:
            hit.append(point)
            raise OSError(errno.ENOSPC, "Synthetic preparation allocation failure.")
    def mkdir(name, *args, **kwargs):
        if os.fsdecode(name) == stage.name:
            fail("mkdir")
        return originals["mkdir"](name, *args, **kwargs)
    def opened(name, *args, **kwargs):
        if name in (b"data", b"chunks"):
            fail(os.fsdecode(name) + "-create")
        return originals["open"](name, *args, **kwargs)
    def sync(fd):
        target = os.readlink(f"/proc/self/fd/{fd}")
        point = {str(path): "parent-sync", str(stage): "stage-sync",
                 str(stage / "data"): "data-sync", str(stage / "chunks"): "chunks-sync"}.get(target)
        fail(point)
        return originals["fsync"](fd)
    def save(base, record):
        if record["state"] == "running":
            fail("ready-save")
        return original_save(base, record)
    with monkeypatch.context() as patch:
        patch.setattr(file_transfer.os, "mkdir", mkdir)
        patch.setattr(file_transfer.os, "open", opened)
        patch.setattr(file_transfer.os, "fsync", sync)
        patch.setattr(file_transfer, "save", save)
        with pytest.raises(Failure):
            await service.transfers.upload(operation["id"], item["id"], actor, 0, b"x", hashlib.sha256(b"x").hexdigest())
    assert hit == [boundary]
    assert (path / "target").stat().st_ino == inode and (path / "target").read_bytes() == b"original"
    if recovery == "resume":
        result = await service.transfers.change(operation["id"], [item["id"]], actor, resume=True)
        assert result["items"][0]["offset"] == 0
        await service.transfers.upload(operation["id"], item["id"], actor, 0, b"x", hashlib.sha256(b"x").hexdigest())
        assert (await service.transfers.finish(operation["id"], item["id"], actor))["state"] == "succeeded"
        assert (path / "target").read_bytes() == b"x"
    else:
        result = await service.transfers.change(operation["id"], [item["id"]], actor, discard=True)
        assert result["state"] == "cancelled"
        assert (path / "target").stat().st_ino == inode and (path / "target").read_bytes() == b"original"
    assert not stage.exists() and not service.transfers.active(root_id=root["id"])
    assert service.files.unregister(root["id"]) == {"ok": True}


async def test_discard_retries_after_partial_cleanup_without_resuming(files_fixture, monkeypatch):
    service, actor, root, path = files_fixture
    operation, _ = await admitted(service, actor, [{"name": "target", "size": 1}], root, "upload")
    item = operation["items"][0]
    await service.transfers.upload(operation["id"], item["id"], actor, 0, b"x", hashlib.sha256(b"x").hexdigest())
    original = file_transfer.os.unlink
    def interrupted(name, *args, **kwargs):
        if name == b"chunks":
            raise OSError(errno.EIO, "Synthetic partial cleanup interruption.")
        return original(name, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(file_transfer.os, "unlink", interrupted)
        with pytest.raises(Failure):
            await service.transfers.change(operation["id"], [item["id"]], actor, discard=True)
    stage = path / (".ficc-transfer-" + item["id"])
    assert stage.exists() and not (stage / "data").exists() and (stage / "chunks").exists()
    assert service.transfers.active(root_id=root["id"])
    with pytest.raises(Failure, match="resumed"):
        await service.transfers.change(operation["id"], [item["id"]], actor, resume=True)
    result = await service.transfers.change(operation["id"], [item["id"]], actor, discard=True)
    assert result["state"] == "cancelled" and not stage.exists() and not (path / "target").exists()
    assert service.files.unregister(root["id"]) == {"ok": True}


async def test_unprepared_stage_refuses_changed_bytes_and_can_be_discarded(files_fixture, monkeypatch):
    service, actor, root, path = files_fixture
    operation, _ = await admitted(service, actor, [{"name": "target", "size": 1}], root, "upload")
    item = operation["items"][0]
    original = file_transfer.save
    def interrupted(base, record):
        if record["state"] == "running":
            raise OSError(errno.ENOSPC, "Synthetic preparation receipt failure.")
        return original(base, record)
    with monkeypatch.context() as patch:
        patch.setattr(file_transfer, "save", interrupted)
        with pytest.raises(Failure):
            await service.transfers.upload(operation["id"], item["id"], actor, 0, b"x", hashlib.sha256(b"x").hexdigest())
    stage = path / (".ficc-transfer-" + item["id"])
    (stage / "data").write_bytes(b"unexpected")
    with pytest.raises(Failure, match="changed"):
        await service.transfers.change(operation["id"], [item["id"]], actor, resume=True)
    assert (stage / "data").read_bytes() == b"unexpected" and not (path / "target").exists()
    result = await service.transfers.change(operation["id"], [item["id"]], actor, discard=True)
    assert result["state"] == "cancelled" and not stage.exists()
