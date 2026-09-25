# SPDX-License-Identifier: Apache-2.0
"""Reject unsafe inputs and changed source archives before release assembly."""

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from release_lib.common import archive_tree, fetch, snapshot, unpack  # noqa: E402
from release_lib.payload import repair_records  # noqa: E402


@pytest.mark.parametrize("kind", ["parent", "absolute", "escape-link", "device"])
def test_archive_rejects_unsafe_members(tmp_path, kind):
    path = tmp_path / "input.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        name = "../outside" if kind == "parent" else "/outside" if kind == "absolute" else "item"
        item = tarfile.TarInfo(name)
        if kind == "escape-link":
            item.type, item.linkname = tarfile.SYMTYPE, "../../outside"
        elif kind == "device":
            item.type = tarfile.CHRTYPE
        archive.addfile(item, io.BytesIO())
    with pytest.raises((ValueError, tarfile.FilterError)):
        unpack(path, tmp_path / "output")
    assert not (tmp_path / "outside").exists()


def test_release_archive_refuses_external_links(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "link").symlink_to("../../outside")
    with pytest.raises(ValueError, match="escapes"):
        archive_tree(source, tmp_path / "out.tar.gz", 1)


@pytest.mark.parametrize("count", [1, 64])
def test_source_archive_rebuild_checks_every_source_file(tmp_path, count):
    source = tmp_path / "source"
    source.mkdir()
    files = {}
    for i in range(count):
        name, data = f"file-{i}.txt", f"distinct source {i}".encode()
        (source / name).write_bytes(data)
        files[name] = hashlib.sha256(data).hexdigest()
    provenance = {"commit": "a" * 40, "dirty": False, "epoch": 1, "files": files}
    (source / "release-source.json").write_text(json.dumps(provenance))
    assert snapshot(source, tmp_path / "copy", False) == provenance
    (source / f"file-{count - 1}.txt").write_text("changed")
    with pytest.raises(ValueError, match="differs"):
        snapshot(source, tmp_path / "changed", False)


def test_cached_download_requires_exact_digest(tmp_path):
    data = b"expected input"
    item = {"id": "test", "name": "input", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "url": "https://github.com/example/input"}
    (tmp_path / "input").write_bytes(data)
    assert fetch({"inputs": [item]}, tmp_path)["test"].read_bytes() == data
    (tmp_path / "input").write_bytes(b"tampered input")
    with pytest.raises(ValueError, match="pinned hash"):
        fetch({"inputs": [item]}, tmp_path)


def test_distribution_record_cannot_escape_payload(tmp_path):
    site = tmp_path / "site"
    record = site / "example.dist-info/RECORD"
    record.parent.mkdir(parents=True)
    record.write_text("../../outside,,\n")
    with pytest.raises(ValueError, match="escapes"):
        repair_records(site, tmp_path)


def test_privacy_audit_reads_nested_archive_members():
    from audit_release import Audit

    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:gz") as archive:
        data = b"synthetic-private-host-47"
        item = tarfile.TarInfo("metadata.txt")
        item.size = len(data)
        archive.addfile(item, io.BytesIO(data))
    audit = Audit(["synthetic-private-host-47"])
    audit.data("source.tar.gz", inner.getvalue())
    assert audit.files == 2 and audit.findings == ["source.tar.gz!metadata.txt"]


def test_privacy_audit_requires_original_upstream_bytes():
    from audit_release import Audit

    data = b"unmodified upstream source"
    audit = Audit(["private-marker"], {"upstream.tar.gz": hashlib.sha256(data).hexdigest()})
    audit.data("sources!upstream.tar.gz", data)
    assert audit.verified_sources == ["sources!upstream.tar.gz"]
    with pytest.raises(ValueError, match="differs"):
        audit.data("sources!upstream.tar.gz", data + b" changed")


def test_archives_use_canonical_permissions(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "data").write_text("data")
    (root / "data").chmod(0o664)
    (root / "command").write_text("command")
    (root / "command").chmod(0o775)
    archive_tree(root, tmp_path / "source.tar.gz", 123)
    with tarfile.open(tmp_path / "source.tar.gz") as archive:
        assert archive.getmember("source/data").mode == 0o644
        assert archive.getmember("source/command").mode == 0o755
        assert all(item.mtime == 123 for item in archive)
