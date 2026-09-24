# SPDX-License-Identifier: Apache-2.0
"""Exercise registered byte names, descriptor boundaries, and confirmed mutations."""

import asyncio
import base64
import os
from types import SimpleNamespace

import pytest

from ficc.auth import Auth
from ficc.errors import Failure
from ficc.files import Files
from ficc.settings import Settings
from ficc.store import Store
from ficc.transfers import Transfers


@pytest.fixture
async def files_fixture(tmp_path):
    settings = Settings(state_dir=tmp_path / "state", control=False)
    store = Store(settings.state_dir / "state.sqlite3")
    service = SimpleNamespace(settings=settings, store=store, auth=Auth(store), live=lambda: None, ssh=None)
    service.files = Files(service)
    service.transfers = Transfers(service)
    _, actor = service.auth.issue("token")
    path = tmp_path / "root"
    path.mkdir()
    root = await service.files.register(str(path), "Work files")
    try:
        yield service, actor.id, root, path
    finally:
        await service.transfers.close()
        await service.files.close()
        store.close()


async def listing(service, actor, root, entry=None, **values):
    return await service.files.listing({"root_id": root["id"], "entry_id": entry or service.files.refs.issue(root, root["reference"]),
                                        "cursor": None, "limit": 100, **values}, actor)


async def mutate(service, actor, root, action, entries=(), **values):
    body = {"action": action, "root_id": root["id"], "entries": list(entries), **values}
    preview = await service.files.preview(body, actor)
    result = await service.files.submit(preview["preview_id"], "test-mutation-" + preview["preview_id"], actor)
    await asyncio.gather(*list(service.files.tasks))
    return service.files.store.get(result["id"]), preview


@pytest.mark.parametrize("count", [1, 64])
async def test_byte_names_pagination_preview_and_delete(files_fixture, count):
    service, actor, root, path = files_fixture
    for index in range(count):
        name = f"file-{index:02}-".encode() + b"\xff<name>\n"
        fd = os.open(os.fsencode(path) + b"/" + name, os.O_CREAT | os.O_WRONLY, 0o600)
        os.write(fd, bytes([index]))
        os.close(fd)
    first = await listing(service, actor, root, limit=1)
    assert len(first["entries"]) == 1
    assert "\\xff" in first["entries"][0]["name"] and "\\n" in first["entries"][0]["name"]
    entries = first["entries"]
    cursor = first["next_cursor"]
    while cursor:
        page = await listing(service, actor, root, cursor=cursor, limit=7)
        entries.extend(page["entries"])
        cursor = page["next_cursor"]
    assert len(entries) == count and len({entry["entry_id"] for entry in entries}) == count
    preview = await service.files.content_preview({"root_id": root["id"], "entry_id": entries[0]["entry_id"], "limit": 65536}, actor)
    assert base64.b64decode(preview["data_base64"]) == b"\0"
    result, frozen = await mutate(service, actor, root, "delete", [entry["entry_id"] for entry in entries])
    assert frozen["count"] == count and result["state"] == "succeeded"
    assert not list(path.iterdir())
    repeated = await service.files.submit(frozen["preview_id"], result["key"], actor)
    assert repeated["id"] == result["id"] and len(service.files.store.all()) == 1


async def test_root_and_entry_grants_and_tamper(files_fixture):
    service, actor, root, path = files_fixture
    (path / "plain").write_bytes(b"safe")
    view = await listing(service, actor, root)
    _, restricted = service.auth.issue("token", scopes=["files:read"], root_ids=[])
    with pytest.raises(Failure, match="permit"):
        await listing(service, restricted.id, root)
    _, readable = service.auth.issue("token", scopes=["files:read"], root_ids=[root["id"]])
    assert len((await listing(service, readable.id, root))["entries"]) == 1
    with pytest.raises(Failure):
        await mutate(service, readable.id, root, "delete", [view["entries"][0]["entry_id"]])
    token = view["entries"][0]["entry_id"]
    with pytest.raises(Failure, match="reference"):
        service.files.resolve(root["id"], token[:-5] + "abcde", actor)
    service.auth.revoke(readable.id)
    with pytest.raises(Failure):
        await listing(service, readable.id, root)


async def test_symlinks_special_files_and_replaced_root(files_fixture, tmp_path):
    service, actor, root, path = files_fixture
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"hidden")
    (path / "link").symlink_to(outside, target_is_directory=True)
    os.mkfifo(path / "pipe")
    entries = {entry["name"]: entry for entry in (await listing(service, actor, root))["entries"]}
    assert entries["link"]["kind"] == "symlink" and entries["pipe"]["kind"] == "special"
    for entry in entries.values():
        with pytest.raises(Failure):
            await service.files.content_preview({"root_id": root["id"], "entry_id": entry["entry_id"], "limit": 100}, actor)
    with pytest.raises(Failure):
        await service.files.register(str(path / "link"), "Linked root")
    path.rename(tmp_path / "old-root")
    path.mkdir()
    with pytest.raises(Failure, match="replaced"):
        await listing(service, actor, root)


async def test_directory_rename_mode_and_stale_selection(files_fixture):
    service, actor, root, path = files_fixture
    root_entry = service.files.refs.issue(root, root["reference"])
    result, _ = await mutate(service, actor, root, "mkdir", parent_id=root_entry, name="child")
    assert result["state"] == "succeeded" and (path / "child").is_dir()
    entry = (await listing(service, actor, root))["entries"][0]
    result, _ = await mutate(service, actor, root, "rename", [entry["entry_id"]], parent_id=root_entry, name="renamed")
    assert result["state"] == "succeeded" and (path / "renamed").is_dir()
    entry = (await listing(service, actor, root))["entries"][0]
    result, _ = await mutate(service, actor, root, "mode", [entry["entry_id"]], mode=0o750)
    assert result["state"] == "succeeded" and (path / "renamed").stat().st_mode & 0o777 == 0o750
    (path / "file").write_bytes(b"first")
    entry = next(entry for entry in (await listing(service, actor, root))["entries"] if entry["name"] == "file")
    (path / "file").write_bytes(b"changed")
    with pytest.raises(Failure, match="changed"):
        await mutate(service, actor, root, "delete", [entry["entry_id"]])
    assert (path / "file").read_bytes() == b"changed"


async def test_parent_moved_outside_is_refused_before_lookup(files_fixture, tmp_path):
    service, actor, root, path = files_fixture
    (path / "child").mkdir()
    child = (await listing(service, actor, root))["entries"][0]
    (path / "child").rename(tmp_path / "moved")
    with pytest.raises(Failure):
        await mutate(service, actor, root, "mkdir", parent_id=child["entry_id"], name="bad")
    assert not (tmp_path / "moved/bad").exists()


async def test_zero_mode_can_be_repaired_without_read_access(files_fixture):
    service, actor, root, path = files_fixture
    (path / "locked").write_bytes(b"private")
    (path / "locked").chmod(0)
    entry = (await listing(service, actor, root))["entries"][0]
    result, _ = await mutate(service, actor, root, "mode", [entry["entry_id"]], mode=0o600)
    assert result["state"] == "succeeded" and (path / "locked").read_bytes() == b"private"


@pytest.mark.parametrize("count", [1, 64])
async def test_mode_batch_preserves_every_identity_and_content(files_fixture, count):
    service, actor, root, path = files_fixture
    originals = {}
    for index in range(count):
        target = path / f"mode-{index:02}.bin"
        target.write_bytes(bytes([index]) * (index + 1))
        target.chmod(0o600)
        originals[target.name] = (target.stat().st_ino, target.read_bytes())
    entries = (await listing(service, actor, root))["entries"]
    assert len(entries) == count and len({item["entry_id"] for item in entries}) == count
    result, preview = await mutate(service, actor, root, "mode", [item["entry_id"] for item in entries], mode=0o640)
    assert preview["count"] == count and result["state"] == "succeeded"
    assert len(result["items"]) == count and all(item["state"] == "succeeded" for item in result["items"])
    for name, (inode, content) in originals.items():
        target = path / name
        assert target.stat().st_mode & 0o777 == 0o640
        assert target.stat().st_ino == inode and target.read_bytes() == content
