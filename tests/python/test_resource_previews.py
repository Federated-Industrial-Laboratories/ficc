# SPDX-License-Identifier: Apache-2.0
"""Refuse accumulated transfer metadata when an earlier source loses access."""

import base64

import pytest
from resource_fixtures import resource_console as resource_console
from test_files import listing
from test_identity_projects import member


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("kind", ["copy", "download"])
async def test_transfer_preview_rechecks_all_sources(resource_console, tmp_path, monkeypatch, count, kind):
    client, service = resource_console
    roots = []
    for label in ("Earlier", "Later", "Destination"):
        path = tmp_path / label
        path.mkdir()
        if label != "Destination":
            for index in range(count):
                (path / f"{label}-{index:02}.txt").write_text(f"{label} private text {index}")
        roots.append(await service.files.register(str(path), label))
    _, control_project, control, _ = member(service, "Unaffected control")
    root_ids = [root["id"] for root in roots]
    service.auth.resources.save(control_project["id"], [], root_ids, 0)
    entries = [sorted((await listing(service, control.id, root))["entries"], key=lambda entry: entry["name"])
               for root in roots[:2]]
    exchange = service.files.transport.exchange
    for index in range(count):
        _, project, actor, headers = member(service, f"Preview reader {index}")
        service.auth.resources.save(project["id"], [], root_ids, 0)
        revoked = False

        async def revoke(root, request, *args):
            nonlocal revoked
            result = await exchange(root, request, *args)
            if root["id"] == roots[1]["id"] and request["action"] == "file.stat" and not revoked:
                service.auth.resources.save(project["id"], [], root_ids[1:], 1)
                revoked = True
            return result

        sources = [{"root_id": root["id"], "entry_id": selected[index]["entry_id"]}
                   for root, selected in zip(roots[:2], entries, strict=True)]
        body = {"kind": kind, "sources": sources}
        if kind == "copy":
            body["destination"] = {"root_id": roots[2]["id"],
                                   "entry_id": service.files.refs.issue(roots[2], roots[2]["reference"])}
        before = set(service.transfers.previews)
        with monkeypatch.context() as patch:
            patch.setattr(service.files.transport, "exchange", revoke)
            response = client.post("/api/v1/transfer-previews", headers=headers, json=body)
        assert revoked and service.auth.current(actor.id).project_roots == sorted(root_ids[1:])
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "denied"
        assert set(service.transfers.previews) == before
        probe = {**sources[0], "limit": 100}
        assert client.post("/api/v1/files/preview", headers=headers, json=probe).status_code == 403
        unchanged = await service.files.content_preview(probe, control.id)
        assert base64.b64decode(unchanged["data_base64"]) == f"Earlier private text {index}".encode()
        allowed = await service.transfers.preview(body, control.id)
        assert [(item["name"], item["size"]) for item in allowed["items"]] == [
            (f"{label}-{index:02}.txt", len(f"{label} private text {index}")) for label in ("Earlier", "Later")]
        service.transfers.previews.pop(allowed["preview_id"])
    assert not list((tmp_path / "Destination").iterdir())
