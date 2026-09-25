# SPDX-License-Identifier: Apache-2.0
"""Inspect compressed packages and archive metadata in every supported input form."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import audit_release  # noqa: E402
from release_lib.common import normalize_sdist, normalize_tree  # noqa: E402

MARKER = "synthetic-private-host-47"


@pytest.mark.parametrize("kind", ["deb-data", "deb-control", "arch", "AppImage"])
@pytest.mark.parametrize("form", ["direct", "directory", "nested"])
def test_native_audit_expands_each_input_form(tmp_path, monkeypatch, kind, form):
    folder = tmp_path / "release"
    folder.mkdir()
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "marker").write_text(MARKER if kind != "deb-control" else "public data")
    if kind.startswith("deb"):
        control = payload / "DEBIAN"
        control.mkdir()
        (control / "control").write_text("Package: test\nVersion: 1\nArchitecture: all\nMaintainer: Example\nDescription: Fixture\n")
        script = control / "preinst"
        script.write_text("#!/bin/sh\n# " + (MARKER if kind == "deb-control" else "public") + "\nexit 0\n")
        script.chmod(0o755)
        package = folder / "test.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(payload), str(package)], check=True, capture_output=True)
    elif kind == "arch":
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            archive.add(payload, arcname="payload")
        package = folder / "test.pkg.tar.zst"
        package.write_bytes(subprocess.check_output(["zstd", "-q", "-c"], input=data.getvalue()))
    else:
        prefix = b"synthetic-runtime" + bytes(16)
        monkeypatch.setattr(audit_release, "runtime_input", lambda: {
            "size": len(prefix), "digest_md5_offset": len(prefix) - 16,
            "sha256": hashlib.sha256(prefix).hexdigest(),
        })
        squash = tmp_path / "payload.squashfs"
        subprocess.run(["mksquashfs", str(payload), str(squash), "-noappend", "-no-progress", "-processors", "1"],
                       check=True, capture_output=True)
        package = folder / "test.AppImage"
        package.write_bytes(prefix + squash.read_bytes())
    audit = audit_release.Audit([MARKER])
    if form == "nested":
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            archive.add(package, arcname=package.name)
        audit.data("outer.tar.gz", data.getvalue())
    else:
        audit.path(folder if form == "directory" else package)
    assert audit.findings
    expected = "preinst" if kind == "deb-control" else "marker"
    assert any(expected in finding for finding in audit.findings)


@pytest.mark.parametrize("field", ["uname", "gname", "pax", "name", "link"])
def test_tar_metadata_is_private_content(field):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        item = tarfile.TarInfo("public")
        if field == "pax":
            item.pax_headers = {"comment": MARKER}
        elif field == "name":
            item.name = MARKER
        elif field == "link":
            item.type, item.linkname = tarfile.SYMTYPE, MARKER
        else:
            setattr(item, field, MARKER)
        archive.addfile(item, io.BytesIO())
    audit = audit_release.Audit([json.dumps(MARKER) if field in {"uname", "gname"} else MARKER])
    audit.data("source.tar.gz", data.getvalue())
    assert audit.findings


def test_identifier_boundaries_preserve_real_host_matches():
    audit = audit_release.Audit(["samplehost", "sample-host", "/private/build/"])
    audit.data("library.py", b"samplehosts samplesamplehost sample-hosting")
    assert not audit.findings
    for index, data in enumerate((b"ssh samplehost", b"Host SAMPLE-HOST", b"/private/build/source.py")):
        audit.data(f"private-{index}", data)
    assert audit.findings == ["private-0", "private-1", "private-2"]


def test_source_distribution_removes_local_archive_metadata(tmp_path):
    source = tmp_path / "dist.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        item = tarfile.TarInfo("distribution/module.py")
        item.uname = item.gname = MARKER
        item.uid = item.gid = 1234
        item.mtime = 987654.125
        item.pax_headers = {"comment": MARKER, "mtime": "987654.125"}
        item.size = 4
        archive.addfile(item, io.BytesIO(b"code"))
    normalize_sdist(source, tmp_path, 123)
    with tarfile.open(source) as archive:
        for item in archive:
            assert (item.uid, item.gid, item.uname, item.gname, item.mtime) == (0, 0, "root", "root", 123)
            assert not item.pax_headers
        assert archive.extractfile("distribution/module.py").read() == b"code"
    audit = audit_release.Audit([MARKER])
    audit.path(source)
    assert not audit.findings


def test_tree_times_include_links_without_touching_external_target(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("preserved")
    os.utime(outside, (456, 456))
    (root / "link").symlink_to(outside)
    (root / "file").write_text("data")
    normalize_tree(root, 123)
    assert all(p.lstat().st_mtime == 123 for p in [root, *root.iterdir()])
    assert outside.stat().st_mtime == 456
