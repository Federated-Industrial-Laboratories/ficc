# SPDX-License-Identifier: Apache-2.0
"""Qualify editor batches through an installed helper and real isolated SSH."""

import importlib.util
import secrets
from pathlib import Path

import pytest
from test_module_editor import entries, install_editor, save_body

from ficc.errors import Failure
from ficc.module_editor_service import Editor
from ficc.module_editor_store import validate_records
from ficc.service import Service

spec = importlib.util.spec_from_file_location("editor_ssh_fixture", Path(__file__).parents[1] / "integration/test_ssh.py")
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)
ssh_fixture = fixture_module.ssh_fixture


@pytest.mark.parametrize("count", [1, 64])
async def test_real_ssh_editor_batch_and_current_authority(ssh_fixture, count):
    transport, home, _ = ssh_fixture
    service = Service(transport.settings)
    service.ssh = transport
    service.module_editor = Editor(service)
    _, actor = service.auth.issue("token")
    preview = await transport.preview("fixture-node", "Editor test")
    await transport.install(preview)
    node = {**preview, "id": "a" * 32, "helper_version": "3"}
    service.store.save_node(node)
    path = home / "editor"
    path.mkdir()
    try:
        for index in range(count):
            item = path / f"file-{index:02}.txt"
            item.write_text(f"Original {index}\n")
            item.chmod(0o640)
        root = await service.files.register(str(path), "SSH text", node["id"])
        workspace = service.workspaces.create("Remote editor")
        context, package, grants = install_editor(service, workspace, [root])
        locations = await entries(service, actor.id, root)
        result = await service.module_editor.read(actor.id, {**context, "items": locations})
        assert [item["data"]["text"] for item in result["results"]] == [f"Original {index}\n" for index in range(count)]
        key = secrets.token_hex(16)
        body = save_body(context, result["results"])
        saved = await service.module_editor.save(actor.id, body, key)
        assert saved["state"] == "succeeded", saved
        for index in range(count):
            file = path / f"file-{index:02}.txt"
            assert file.read_text() == f"Changed {index}\n"
            assert file.stat().st_mode & 0o7777 == 0o640
        replay = await service.module_editor.save(actor.id, body, key)
        assert replay["items"] == saved["items"]
        receipt = {**context, "operation_id": key}
        retained = await service.module_editor.recovery(actor.id, {**receipt, "item_id": saved["items"][-1]["id"], "copy": "original"})
        assert retained["text"] == f"Original {count - 1}\n"
        service.modules.set_enabled(package, False, [])
        with pytest.raises(Failure):
            await service.module_editor.status(actor.id, receipt)
        service.modules.set_enabled(package, True, grants)
        service.store.save_node({**node, "fingerprint": "SHA256:changed-test-identity"})
        with pytest.raises(Failure, match="identity"):
            await service.module_editor.recovery(actor.id, {**receipt, "item_id": saved["items"][0]["id"], "copy": "draft"})
        service.store.save_node(node)
        cleaned = await service.module_editor.cleanup(actor.id, {**receipt, "item_ids": [item["id"] for item in saved["items"]], "confirm": True})
        assert not any(item["retained"] for item in cleaned["items"])
        validate_records(service.store.db, quiescent=True)
        await service.module_editor.remove(actor.id, receipt)
        assert not list((home / ".local/state/ficc/files").glob("*/*.json"))
        locations = await entries(service, actor.id, root)
        before = await service.module_editor.read(actor.id, {**context, "items": [locations[0]]})
        (path / "file-00.txt").write_text("External\n")
        stale = await service.module_editor.save(actor.id, save_body(context, before["results"]), secrets.token_hex(16))
        assert stale["state"] == "failed" and (path / "file-00.txt").read_text() == "External\n"
        (path / "link.txt").symlink_to(home / "outside")
        locations = await entries(service, actor.id, root)
        result = await service.module_editor.read(actor.id, {**context, "items": locations[-1:]})
        assert result["results"][0]["error"]
        service.modules.set_enabled(package, True, grants[:2])
        locations = await entries(service, actor.id, root)
        result = await service.module_editor.read(actor.id, {**context, "items": locations[:1]})
        assert result["results"][0]["data"]["writable"] is False
        _, scoped = service.auth.issue("token", scopes=["files:read", "workspaces:read"], root_ids=[])
        denied = await service.module_editor.read(scoped.id, {**context, "items": locations[:1]})
        assert denied["results"][0]["error"]["code"] == "denied"
        assert not list(path.glob(".ficc-editor-*"))
    finally:
        await service.files.close()
        await service.transfers.close()
        await service.ssh.close()
        service.close()
