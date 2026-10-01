# SPDX-License-Identifier: Apache-2.0
"""Refuse release inventories that conceal changed or unlisted module archives."""

import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from release_lib.modules import components  # noqa: E402


def fixture(packages, count):
    rows = []
    for index in range(count):
        identity = f"org.example.module{index}"
        name = identity + "-1.0.0.ficc-module.zip"
        with zipfile.ZipFile(packages / name, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"id": identity, "version": "1.0.0",
                                                         "runtime": {"kind": "native"}}))
            archive.writestr("program", f"distinct program {index}")
        rows.append({"id": identity, "version": "1.0.0", "filename": name,
                     "digest": hashlib.sha256((packages / name).read_bytes()).hexdigest()})
    (packages / "index.json").write_text(json.dumps({"version": 1, "modules": rows}))
    return rows


@pytest.mark.parametrize("count", [1, 64])
def test_shipped_module_inventory_binds_distinct_archives(tmp_path, count):
    rows = fixture(tmp_path, count)
    result = components(tmp_path)
    assert len(result) == count
    assert {item["bom-ref"] for item in result} == {"urn:ficc:module:" + row["digest"] for row in rows}
    assert {(item["name"], item["hashes"][0]["content"]) for item in result} == {
        (row["id"], row["digest"]) for row in rows}


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("change", ["bytes", "identity", "unlisted", "duplicate", "path", "link"])
def test_shipped_module_inventory_refuses_mismatches(tmp_path, count, change):
    rows = fixture(tmp_path, count)
    target = tmp_path / rows[-1]["filename"]
    if change == "bytes":
        target.write_bytes(target.read_bytes() + b"changed")
    elif change == "identity":
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"id": "org.example.other", "version": "1.0.0",
                                                         "runtime": {"kind": "native"}}))
        rows[-1]["digest"] = hashlib.sha256(target.read_bytes()).hexdigest()
    elif change == "unlisted":
        (tmp_path / "unlisted.ficc-module.zip").write_bytes(target.read_bytes())
    elif change == "duplicate":
        rows.append(dict(rows[-1]))
    elif change == "path":
        rows[-1]["filename"] = "../" + rows[-1]["filename"]
    else:
        moved = tmp_path / "original.zip"
        target.rename(moved)
        target.symlink_to(moved.name)
    (tmp_path / "index.json").write_text(json.dumps({"version": 1, "modules": rows}))
    with pytest.raises(ValueError):
        components(tmp_path)
