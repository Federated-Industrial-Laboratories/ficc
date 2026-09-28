# SPDX-License-Identifier: Apache-2.0
"""Verify supplied archives use the inspected, disabled installation path."""

import hashlib
import json

import pytest
from test_modules_packages import bundle, package

from ficc import module_bundle
from ficc.errors import Failure


@pytest.fixture
def supplied(tmp_path, monkeypatch):
    original = module_bundle.importlib.resources.files
    monkeypatch.setattr(module_bundle.importlib.resources, "files",
                        lambda name: tmp_path if name == "ficc" else original(name))
    root = tmp_path / "module_packages"
    root.mkdir()
    data = bundle(*package())
    manifest = package()[0]
    name = f"{manifest['id']}-{manifest['version']}.ficc-module.zip"
    entry = {"id": manifest["id"], "version": manifest["version"], "display_name": "Test module",
             "filename": name, "digest": hashlib.sha256(data).hexdigest()}
    (root / name).write_bytes(data)
    (root / "index.json").write_text(json.dumps({"version": 1, "modules": [entry]}))
    return root, entry, data


def test_supplied_module_inspection_install_and_grants_are_separate(console, supplied):
    client, service = console
    _, entry, _ = supplied
    assert client.get("/api/v1/supplied-modules").json() == {"modules": [entry]}
    assert service.modules.list() == []
    preview = client.post("/api/v1/supplied-module-previews", json={"package_id": entry["id"]})
    assert preview.status_code == 200, preview.text
    assert preview.json()["digest"] == entry["digest"]
    request = {"preview_id": preview.json()["preview_id"], "digest": entry["digest"], "accept_unverified": False}
    assert client.post("/api/v1/modules", json=request).status_code == 409
    assert service.modules.list() == []
    request["accept_unverified"] = True
    result = client.post("/api/v1/modules", json=request)
    assert result.status_code == 201, result.text
    installed = service.modules.get(entry["digest"])
    assert installed["enabled"] is False and installed["grants"] == []


@pytest.mark.parametrize("fault", ["changed", "missing", "oversize"])
def test_supplied_archive_damage_fails_before_inspection(supplied, fault):
    root, entry, data = supplied
    path = root / entry["filename"]
    if fault == "missing":
        path.unlink()
    elif fault == "oversize":
        with path.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
    else:
        path.write_bytes(data + b"changed")
    with pytest.raises(Failure) as error:
        module_bundle.read(entry["id"])
    assert error.value.code == "module_bundle_invalid"


@pytest.mark.parametrize("fault", ["duplicate", "path", "capacity"])
def test_supplied_index_refuses_ambiguous_or_unsafe_entries(supplied, fault):
    root, entry, _ = supplied
    entries = [entry]
    if fault == "duplicate":
        entries *= 2
    elif fault == "capacity":
        entries *= 33
    else:
        entry["filename"] = "../module.zip"
    (root / "index.json").write_text(json.dumps({"version": 1, "modules": entries}))
    with pytest.raises(Failure):
        module_bundle.available()
