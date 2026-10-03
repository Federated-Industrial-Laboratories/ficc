# SPDX-License-Identifier: Apache-2.0
"""Opt-in real S3 version, checksum, multipart resume and reconciliation contract."""

import asyncio
import hashlib
import json
import os
from pathlib import Path

import pytest
from test_files import files_fixture as files_fixture
from test_files import listing

from ficc.datasets import Datasets
from ficc.secret_cli import initialize
from ficc.secrets import Secrets
from ficc.sources import Sources


@pytest.mark.skipif(not os.environ.get("FICC_SOURCE_S3_PORT"), reason="Dedicated S3 fixture is opt-in.")
async def test_versioned_read_resumed_multipart_verified_completion_and_abort(files_fixture):
    service, actor, root, path = files_fixture
    fixture = Path(os.environ["FICC_SOURCE_FIXTURES"])
    initialize(service.settings.state_dir, service.settings.state_dir.parent / "source-key")
    secrets = Secrets(service.settings.state_dir)
    for role in ("reader", "writer"):
        secrets.put(role, (fixture / f"s3-{role}.json").read_bytes())
    service.datasets, service.sources = Datasets(service), Sources(service)
    connection = await service.sources.create({"name": "S3 fixture", "provider": "s3",
        "configuration": {"bucket": "ficc-025-source-fixture", "prefix": "qualified/"},
        "endpoint": {"host": "127.0.0.1", "port": int(os.environ["FICC_SOURCE_S3_PORT"]), "addresses": ["127.0.0.1"],
            "ca_pem": (fixture / "s3-ca.pem").read_text(), "private_network": True},
        "read_secret": "reader", "write_secret": "writer", "permissions": ["read", "export", "write"]}, "source-s3-fixture-connection", actor)
    catalogue = await service.sources.inspect(connection["id"], actor, "catalogue", {})
    assert any(item["id"] == "qualified/readings.csv" for item in catalogue["resources"])
    shape = await service.sources.inspect(connection["id"], actor, "describe", {"resource": "qualified/readings.csv"})
    query = service.sources.register(connection["id"], {"name": "Pinned CSV object", "specification": {
        "key": "qualified/readings.csv", "version_id": shape["receipt"]["version_id"],
        "sha256": "4c0610aa92b75ca794ceec30068934fc6bc3d2fbff87969a15977f8fcf96f13f"}}, "source-s3-fixture-read", actor)
    preview = await service.sources.preview(query["id"], {}, actor)
    assert preview["receipt"]["read_bytes"] == 24 and preview["receipt"]["partial"]
    run = await service.sources.submit(query["id"], {"format": "original", "destination": {
        "root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"])},
        "filename": "object.csv", "dataset_name": "Object export"}, "source-s3-fixture-export", actor)

    async def finished(identity):
        await asyncio.gather(*list(service.sources.tasks.values()))
        result = service.sources.status(identity, actor)
        assert result["state"] == "completed", json.dumps(result.get("error") or result.get("receipt"))
        return result

    result = await finished(run["id"])
    assert service.datasets.get(result["dataset_id"], actor)["files"][0]["sha256"] == query["query"]["specification"]["sha256"]
    payload = path / "multipart.bin"
    with payload.open("wb") as stream:
        for _ in range(72):
            stream.write(b"verified-part-00\n" * 8192)
    entry = next(item for item in (await listing(service, actor, root))["entries"] if item["name"] == payload.name)
    dataset = await service.datasets.create({"name": "Multipart source", "format": "binary", "schema": {"fields": []},
        "sources": [{"root_id": root["id"], "entry_id": entry["entry_id"]}]}, "source-s3-fixture-dataset", actor)
    upload = await service.sources.uploads.begin(connection["id"], {"key": "qualified/" + dataset["id"] + ".bin", "dataset_id": dataset["id"]}, "source-s3-fixture-upload", actor)
    await finished(upload["last_run_id"])
    upload = service.sources.uploads.get(upload["id"], actor)
    assert upload["parts"] == 2

    async def operation(name, **extra):
        run = await service.sources.uploads.operate(upload["id"], {"operation": name, **extra},
            "source-s3-fixture-" + name + str(extra.get("part_number", "")), actor)
        return await finished(run["id"])

    first = await operation("part", part_number=1)
    assert first["receipt"]["checksum_sha256"]
    await service.sources.close()
    service.sources = Sources(service)
    retained = await operation("status")
    assert [part["part_number"] for part in retained["receipt"]["parts"]] == [1]
    assert retained["receipt"]["parts"][0]["verified"]
    await operation("part", part_number=2)
    completed = await operation("complete")
    assert completed["receipt"]["verification"] == "whole-object-readback"
    with payload.open("rb") as stream:
        assert completed["receipt"]["sha256"] == hashlib.file_digest(stream, "sha256").hexdigest()
    reconciled = await operation("reconcile")
    assert reconciled["receipt"]["reconciled"] and reconciled["receipt"]["version_id"]
    aborted = await service.sources.uploads.begin(connection["id"], {"key": "qualified/" + dataset["id"] + "-aborted.bin", "dataset_id": dataset["id"]}, "source-s3-fixture-abort-begin", actor)
    await finished(aborted["last_run_id"])
    run = await service.sources.uploads.operate(aborted["id"], {"operation": "abort"}, "source-s3-fixture-abort", actor)
    assert (await finished(run["id"]))["receipt"]["outcome"] == "aborted"
