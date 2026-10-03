# SPDX-License-Identifier: Apache-2.0
"""Exercise real project file changes and copies with durable receipt ownership."""

import base64

import pytest
from resource_fixtures import assign
from resource_fixtures import resource_console as resource_console
from test_files import listing, mutate
from test_identity_projects import member
from test_transfers import admitted, completed

from ficc.errors import Failure


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_project_file_mutations_and_copies_keep_ownership(resource_console, tmp_path, count):
    client, service = resource_console
    source, destination = tmp_path / "source", tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    root = await service.files.register(str(source), "Source files")
    target = await service.files.register(str(destination), "Copied files")
    user, project, principal, headers = member(service, "File operator")
    _, outside, attacker, attack = member(service, "Other file project")
    roots = [root["id"], target["id"]]
    assign(client, project, roots=roots)
    assign(client, outside, roots=roots)
    for index in range(count):
        (source / f"data-{index:02}.bin").write_bytes(bytes([index]) * (index + 1))
    entries = (await listing(service, principal.id, root))["entries"]
    operation, _ = await admitted(service, principal.id,
        [{"root_id": root["id"], "entry_id": item["entry_id"]} for item in entries], target)
    copied = await completed(service, operation["id"])
    assert copied["state"] == "succeeded"
    assert (copied["subject_id"], copied["project_id"]) == (user["id"], project["id"])
    assert all((destination / f"data-{index:02}.bin").read_bytes() == bytes([index]) * (index + 1)
               for index in range(count))
    assert client.get("/api/v1/transfers", headers=attack).json() == {"transfers": []}
    assert client.get("/api/v1/transfers/" + copied["id"], headers=attack).status_code == 404
    with pytest.raises(Failure) as denied:
        await service.transfers.change(copied["id"], [item["id"] for item in copied["items"]], attacker.id, discard=True)
    assert denied.value.status == 404

    deleted, _ = await mutate(service, principal.id, root, "delete", [item["entry_id"] for item in entries])
    assert deleted["state"] == "succeeded" and not list(source.iterdir())
    assert (deleted["subject_id"], deleted["project_id"]) == (user["id"], project["id"])
    url = "/api/v1/file-operations/" + deleted["id"]
    assert client.get(url, headers=attack).status_code == 404
    assert client.post(url + "/reconcile", headers=attack).status_code == 404
    assert client.get("/api/v1/file-operations", headers=attack).json() == {"operations": []}
    service.auth.revoke(principal.id)
    token, fresh = service.auth.issue("token", subject_id=user["id"], project_id=project["id"])
    restored = {"Authorization": "Bearer " + token}
    assert client.get(url, headers=restored).json()["subject_id"] == user["id"]
    assert client.get("/api/v1/transfers/" + copied["id"], headers=restored).status_code == 200
    limited, _ = service.auth.issue("token", subject_id=user["id"], project_id=project["id"], node_ids=[])
    assert client.get("/api/v1/file-roots", headers={"Authorization": "Bearer " + limited}).json() == {"roots": []}
    assign(client, project, roots=[], revision=1)
    assert client.get("/api/v1/file-roots", headers=restored).json() == {"roots": []}
    assert client.get("/api/v1/transfers/" + copied["id"], headers=restored).status_code == 404
    assert len((await listing(service, attacker.id, target))["entries"]) == count
    assert fresh.project_id == project["id"]


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_folder_revocation_during_read_does_not_return_bytes(resource_console, tmp_path, monkeypatch, count):
    client, service = resource_console
    path = tmp_path / "documents"
    path.mkdir()
    root = await service.files.register(str(path), "Documents")
    _, control, reader, _ = member(service, "Unaffected reader")
    assign(client, control, roots=[root["id"]])
    for index in range(count):
        (path / f"private-{index:02}.txt").write_text(f"Private project text {index}")
    entries = (await listing(service, reader.id, root))["entries"]
    assert len(entries) == count
    exchange = service.files.transport.exchange
    for index, entry in enumerate(entries):
        _, project, actor, _ = member(service, f"Reader {index}")
        assign(client, project, roots=[root["id"]])
        async def revoke(*args):
            result = await exchange(*args)
            service.auth.resources.save(project["id"], [], [], 1)
            return result
        body = {"root_id": root["id"], "entry_id": entry["entry_id"], "limit": 100}
        with monkeypatch.context() as patch:
            patch.setattr(service.files.transport, "exchange", revoke)
            with pytest.raises(Failure) as denied:
                await service.files.content_preview(body, actor.id)
        assert denied.value.status == 403
        assert service.auth.current(actor.id).id == actor.id
        unchanged = await service.files.content_preview(body, reader.id)
        assert base64.b64decode(unchanged["data_base64"]) == f"Private project text {index}".encode()
        assert (path / f"private-{index:02}.txt").read_text() == f"Private project text {index}"
