# SPDX-License-Identifier: Apache-2.0
"""Exercise lost acknowledgements, revoked grants, and local worker shutdown."""

import asyncio
import errno
import hashlib
import os
import threading

import pytest
from ficc_node import file_transfer
from ficc_node.file_access import CHUNK
from test_files import files_fixture as files_fixture
from test_files import listing, mutate
from test_transfers import admitted, completed, destination

from ficc.errors import Failure
from ficc.transfers import Transfers


async def test_commit_ack_loss_reconciles_without_rewrite(files_fixture, tmp_path, monkeypatch):
    service, actor, root, path = files_fixture
    target = await destination(service, tmp_path / "destination")
    (path / "source").write_bytes(b"final bytes")
    source = (await listing(service, actor, root))["entries"][0]
    original = service.transfers.destination
    async def lost_ack(operation, item, action, **values):
        result = await original(operation, item, action, **values)
        if action == "transfer.commit":
            raise Failure("unreachable", "Commit acknowledgement lost.", 502)
        return result
    monkeypatch.setattr(service.transfers, "destination", lost_ack)
    operation, _ = await admitted(service, actor, [{"root_id": root["id"], "entry_id": source["entry_id"]}], target)
    assert (await completed(service, operation["id"]))["state"] == "unknown"
    before = (tmp_path / "destination/source").stat()
    service.transfers = Transfers(service)
    result = await service.transfers.change(operation["id"], [operation["items"][0]["id"]], actor, resume=True)
    after = (tmp_path / "destination/source").stat()
    assert result["state"] == "succeeded" and before.st_ino == after.st_ino and before.st_mtime_ns == after.st_mtime_ns


async def test_disk_full_preserves_existing_destination(files_fixture, tmp_path, monkeypatch):
    service, actor, root, path = files_fixture
    target = await destination(service, tmp_path / "destination")
    (path / "same").write_bytes(b"replacement")
    (tmp_path / "destination/same").write_bytes(b"original")
    source = (await listing(service, actor, root))["entries"][0]
    original = file_transfer.os.pwrite
    def full(*args, **kwargs):
        raise OSError(errno.ENOSPC, "Synthetic disk full.")
    monkeypatch.setattr(file_transfer.os, "pwrite", full)
    operation, _ = await admitted(service, actor, [{"root_id": root["id"], "entry_id": source["entry_id"]}], target, overwrite=True)
    result = await completed(service, operation["id"])
    assert result["state"] == "interrupted" and (tmp_path / "destination/same").read_bytes() == b"original"
    monkeypatch.setattr(file_transfer.os, "pwrite", original)
    await service.transfers.change(operation["id"], [operation["items"][0]["id"]], actor, discard=True)


async def test_revocation_blocks_accepted_but_undispatched_transfer(files_fixture, tmp_path):
    service, actor, root, path = files_fixture
    target = await destination(service, tmp_path / "destination")
    (path / "source").write_bytes(b"private")
    source = (await listing(service, actor, root))["entries"][0]
    _, grant = service.auth.issue("token", scopes=["files:read", "files:write"], root_ids=[root["id"], target["id"]])
    operation, _ = await admitted(service, grant.id, [{"root_id": root["id"], "entry_id": source["entry_id"]}], target)
    service.auth.revoke(grant.id)
    result = await completed(service, operation["id"])
    assert result["state"] == "interrupted" and not list((tmp_path / "destination").iterdir())


async def test_local_cancel_waits_for_owned_thread(files_fixture, monkeypatch):
    service, actor, root, path = files_fixture
    from ficc import file_transport
    original = file_transport.dispatch
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        try:
            return original(*args, **kwargs)
        finally:
            finished.set()
    monkeypatch.setattr(file_transport, "dispatch", delayed)
    task = asyncio.create_task(service.files.transport.call(root, {"action": "file.root"}))
    for _ in range(100):
        if entered.is_set():
            break
        await asyncio.sleep(0.01)
    assert entered.is_set()
    task.cancel()
    await asyncio.sleep(0.02)
    assert not task.done() and not finished.is_set()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert finished.is_set()


async def test_changed_destination_refuses_overwrite_and_nonempty_delete(files_fixture, tmp_path, monkeypatch):
    service, actor, root, path = files_fixture
    target = await destination(service, tmp_path / "destination")
    (path / "same").write_bytes(b"new")
    (tmp_path / "destination/same").write_bytes(b"first")
    source = (await listing(service, actor, root))["entries"][0]
    preview = await service.transfers.preview({"kind": "copy", "sources": [
        {"root_id": root["id"], "entry_id": source["entry_id"]}],
        "destination": {"root_id": target["id"], "entry_id": service.files.refs.issue(target, target["reference"])},
        "overwrite": True}, actor)
    (tmp_path / "destination/same").write_bytes(b"changed by another program")
    op = await service.transfers.submit(preview["preview_id"], "changed-destination-key", actor)
    assert (await completed(service, op["id"]))["state"] == "interrupted"
    assert (tmp_path / "destination/same").read_bytes() == b"changed by another program"
    (path / "folder").mkdir()
    (path / "folder/keep").write_bytes(b"keep")
    entry = next(value for value in (await listing(service, actor, root))["entries"] if value["name"] == "folder")
    with pytest.raises(Failure, match="empty"):
        await mutate(service, actor, root, "delete", [entry["entry_id"]])
    assert (path / "folder/keep").read_bytes() == b"keep"


async def test_upload_resume_refuses_different_prefix(files_fixture):
    service, actor, root, path = files_fixture
    operation, _ = await admitted(service, actor, [{"name": "upload", "size": CHUNK+1}], root, "upload")
    item_id = operation["items"][0]["id"]
    chunk = b"x" * CHUNK
    await service.transfers.upload(operation["id"], item_id, actor, 0, chunk, hashlib.sha256(chunk).hexdigest())
    await service.transfers.change(operation["id"], [item_id], actor)
    await service.transfers.change(operation["id"], [item_id], actor, resume=True)
    with pytest.raises(Failure, match="prefix"):
        await service.transfers.upload(operation["id"], item_id, actor, CHUNK, b"z", hashlib.sha256(b"z").hexdigest())
    with pytest.raises(Failure, match="prefix"):
        await service.transfers.finish(operation["id"], item_id, actor)
    wrong = b"y" * CHUNK
    with pytest.raises(Failure, match="prefix"):
        await service.transfers.upload(operation["id"], item_id, actor, 0, wrong, hashlib.sha256(wrong).hexdigest())
    assert not (path / "upload").exists()


async def test_resuming_one_item_does_not_authorize_another(files_fixture, tmp_path, monkeypatch):
    from ficc import transfer_work
    service, actor, root, path = files_fixture
    target = await destination(service, tmp_path / "destination")
    for name in ("first", "second"):
        (path / name).write_bytes(name.encode())
    entries = (await listing(service, actor, root))["entries"]
    sources = [{"root_id": root["id"], "entry_id": item["entry_id"]} for item in entries]
    original = service.transfers.start
    monkeypatch.setattr(service.transfers, "start", lambda *args: None)
    operation, _ = await admitted(service, actor, sources, target)
    service.auth.revoke(actor)
    _, replacement = service.auth.issue("token", scopes=["files:read", "files:write"], root_ids=[root["id"], target["id"]])
    monkeypatch.setattr(service.transfers, "start", original)
    first, second = operation["items"]
    await service.transfers.change(operation["id"], [first["id"]], replacement.id, resume=True)
    await completed(service, operation["id"])
    await transfer_work.run(service.transfers, operation["id"], second["id"])
    result = service.transfers.store.get(operation["id"])
    assert result["items"][0]["state"] == "succeeded"
    assert result["items"][1]["state"] == "interrupted"
    assert (tmp_path / "destination/first").read_bytes() == b"first"
    assert not (tmp_path / "destination/second").exists()


async def test_cancelled_download_worker_keeps_descriptor_until_read_finishes(tmp_path):
    from ficc.file_worker import owned
    path = tmp_path / "content"
    path.write_bytes(b"content")
    fd = os.open(path, os.O_RDONLY)
    entered, release, completed_read = threading.Event(), threading.Event(), threading.Event()
    def slow_read():
        entered.set()
        assert release.wait(5)
        result = os.pread(fd, 7, 0)
        completed_read.set()
        return result
    async def response():
        try:
            return await owned(slow_read)
        finally:
            os.close(fd)
    task = asyncio.create_task(response())
    for _ in range(100):
        if entered.is_set():
            break
        await asyncio.sleep(0.01)
    assert entered.is_set()
    task.cancel()
    await asyncio.sleep(0.02)
    assert os.fstat(fd).st_size == 7 and not completed_read.is_set() and not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert completed_read.is_set()
    with pytest.raises(OSError):
        os.fstat(fd)


def test_hash_checks_cancellation_between_bounded_chunks(tmp_path, monkeypatch):
    from ficc_node import file_access
    path = tmp_path / "large"
    path.write_bytes(b"x" * (CHUNK * 3))
    cancel = threading.Event()
    original, calls = os.pread, []
    def interrupted(fd, size, offset):
        data = original(fd, size, offset)
        calls.append((size, offset))
        cancel.set()
        return data
    monkeypatch.setattr(file_access.os, "pread", interrupted)
    with path.open("rb") as stream, pytest.raises(file_access.FileError, match="interrupted"):
        file_access.file_hash(stream.fileno(), cancel=cancel)
    assert calls == [(CHUNK, 0)]


async def test_cleanup_failure_is_visible_and_retry_preserves_commit(files_fixture, monkeypatch):
    service, actor, root, path = files_fixture
    (path / "replace").write_bytes(b"old")
    operation, _ = await admitted(service, actor, [{"name": "replace", "size": 3}], root, "upload", overwrite=True)
    item_id = operation["items"][0]["id"]
    await service.transfers.upload(operation["id"], item_id, actor, 0, b"new", hashlib.sha256(b"new").hexdigest())
    original = file_transfer.cleanup
    def denied(*args, **kwargs):
        raise PermissionError("Synthetic cleanup refusal.")
    monkeypatch.setattr(file_transfer, "cleanup", denied)
    result = await service.transfers.finish(operation["id"], item_id, actor)
    assert result["state"] == "succeeded" and result["items"][0]["cleanup_pending"]
    with pytest.raises(Failure, match="retained"):
        service.files.unregister(root["id"])
    assert (path / "replace").read_bytes() == b"new"
    monkeypatch.setattr(file_transfer, "cleanup", original)
    result = await service.transfers.change(operation["id"], [item_id], actor, discard=True)
    assert not result["items"][0]["cleanup_pending"] and (path / "replace").read_bytes() == b"new"
    assert service.files.unregister(root["id"]) == {"ok": True}
    assert not (path / (".ficc-transfer-" + item_id)).exists()
