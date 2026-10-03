# SPDX-License-Identifier: Apache-2.0
"""Preserve uncertain publication and reclaim only retained export reservations."""

import os
import stat

import pytest
from test_files import files_fixture as files_fixture
from test_sources import exported, source

from ficc import data_sdk, source_output
from ficc.sources import Sources


async def test_export_failure_after_rename_retains_unknown_and_never_replays(files_fixture, monkeypatch):
    service, actor, root, path = files_fixture
    (path / "source.csv").write_text("value\n7\n")
    connection = await source(service, actor, root, "source.csv", "csv", {"schema": {"fields": [{"name": "value", "type": "integer"}]}})
    query = service.sources.register(connection["id"], {"name": "Rows", "specification": {}}, "source-query-publish-fault", actor)
    actual = os.fsync

    def interrupted(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) and (path / "retained.csv").exists():
            raise OSError("Directory synchronization failed after rename")
        actual(fd)

    monkeypatch.setattr(source_output.os, "fsync", interrupted)
    result = await exported(service, actor, root, query, {}, "retained")
    assert result["state"] == "unknown" and result["staging"]["cleanup"] == "published_retained"
    assert (path / "retained.csv").read_text() == "value\n7\n"
    repeated = await exported(service, actor, root, query, {}, "retained")
    assert repeated["id"] == result["id"] and repeated["state"] == "unknown"
    await service.sources.cancel(result["id"], actor)
    assert (path / "retained.csv").read_text() == "value\n7\n"


async def test_restart_partial_export_cleanup_uses_retained_inode(files_fixture):
    service, actor, root, path = files_fixture
    sources = Sources(service)
    value = {**sources.owner(sources.current(actor, "export")), "state": "running", "action": "export", "actor": actor}
    sources.store.insert("source_runs", value, "retained-partial", "0" * 64)

    def retain(staging):
        value["staging"] = staging
        sources.store.save("source_runs", value)

    output = source_output.Output(service, {"root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"])},
        "unpublished.csv", value["id"], actor, {"export_bytes": None, "free_bytes": 0}, retain)
    output.write(b"x" * 262144)
    os.fsync(output.file)
    # Lose the controller object without running its cleanup, leaving real reserved bytes.
    os.close(output.file)
    os.close(output.directory)
    output.file = output.directory = None
    assert (path / output.temporary.decode()).stat().st_blocks > 0
    restored = Sources(service)
    assert restored.status(value["id"], actor)["state"] == "unknown"
    result = await restored.cancel(value["id"], actor)
    assert result["state"] == "unknown" and result["staging"]["cleanup"] == "partial_removed"
    assert not (path / output.temporary.decode()).exists() and not (path / "unpublished.csv").exists()
    assert not restored.tasks


def test_shipped_provider_declares_its_own_api_version(monkeypatch):
    monkeypatch.setattr(data_sdk, "API_VERSION", 2)
    for name in ("sqlite", "csv", "postgresql", "mysql", "arrow", "s3", "duckdb"):
        with pytest.raises(data_sdk.DataError, match="interface is not supported"):
            data_sdk.load(name)
