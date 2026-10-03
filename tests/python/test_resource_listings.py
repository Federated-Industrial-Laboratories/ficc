# SPDX-License-Identifier: Apache-2.0
"""Exclude revoked folders from a response after asynchronous availability checks."""

import pytest
from resource_fixtures import assign
from resource_fixtures import resource_console as resource_console
from test_identity_projects import member


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_root_listing_rechecks_all_assignments_before_return(resource_console, tmp_path, monkeypatch, count):
    client, service = resource_console
    folders = []
    for label in ("Private", "Unchanged"):
        path = tmp_path / label
        path.mkdir()
        folders.append(await service.files.register(str(path), label))
    exchange = service.files.transport.exchange
    for index in range(count):
        _, project, actor, _ = member(service, f"Folder reader {index}")
        assign(client, project, roots=[value["id"] for value in folders])
        async def revoke(root, *args):
            value = await exchange(root, *args)
            # The earlier folder must disappear even when revocation happens during a later probe.
            if root["id"] == folders[1]["id"]:
                service.auth.resources.save(project["id"], [], [folders[1]["id"]], 1)
            return value
        with monkeypatch.context() as patch:
            patch.setattr(service.files.transport, "exchange", revoke)
            result = await service.files.roots(actor.id)
        assert [value["id"] for value in result["roots"]] == [folders[1]["id"]]
        assert result["roots"][0]["available"] is True
        assert service.auth.current(actor.id).id == actor.id
