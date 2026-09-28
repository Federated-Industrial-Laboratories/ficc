# SPDX-License-Identifier: Apache-2.0
"""Verify deterministic SDK packages and the isolated Python process contract."""

import copy
import importlib.util
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

from ficc.errors import Failure
from ficc.modules.archive import inspect_archive

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load("sdk_pack", ROOT / "tools/build-modules.py")
examples = load("sdk_build", ROOT / "sdk/build.py")
conformance = load("sdk_conformance", ROOT / "sdk/conformance.py")


@pytest.mark.parametrize("name,capabilities,component", [
    ("clock", {"workspace:read"}, "clock"),
    ("notes", {"workspace:read", "workspace:write"}, "editor"),
    ("audio-player", {"workspace:read", "workspace:write", "audio:playback"}, "audio-player"),
])
def test_defaults_use_the_same_inspected_archive_path(tmp_path, name, capabilities, component):
    manifest, files = builder.read_source(ROOT / "modules" / name)
    first = builder.publish(manifest, files, tmp_path)
    second = builder.publish(manifest, files, tmp_path)
    assert first.read_bytes() == second.read_bytes()
    checked = inspect_archive(first.read_bytes()).manifest
    assert checked["runtime"] == {"kind": "declarative", "language": "none"}
    assert checked["id"] == "org.ficc." + name
    assert set(checked["capabilities"]) == capabilities
    assert checked["ui"]["children"][0]["type"] == component
    assert checked["actions"] == []
    assert "licenses/FICC-Apache-2.0.txt" in checked["files"]


def test_archive_bytes_are_independent_of_dictionary_order():
    manifest, _ = builder.read_source(ROOT / "modules/notes")
    assert builder.build_archive(manifest, {"b.txt": b"b", "a.txt": b"a"}) == (
        builder.build_archive(dict(reversed(list(manifest.items()))), {"a.txt": b"a", "b.txt": b"b"}))


@pytest.mark.parametrize("name", ["../outside", "manifest.json", "bad/name."])
def test_package_refuses_unsafe_or_reserved_names(name):
    manifest, _ = builder.read_source(ROOT / "modules/notes")
    with pytest.raises((ValueError, Failure)):
        builder.build_archive(manifest, {name: b"bad"})


@pytest.mark.parametrize("kind", ["file-link", "directory-link", "hard-link"])
def test_source_does_not_follow_links(tmp_path, kind):
    source = tmp_path / "source"
    source.mkdir()
    manifest, _ = builder.read_source(ROOT / "modules/notes")
    (source / "manifest.json").write_text(json.dumps(manifest))
    payload = source / "payload"
    payload.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"private")
    if kind == "file-link":
        (payload / "link").symlink_to(outside)
    elif kind == "directory-link":
        (payload / "link").symlink_to(tmp_path, target_is_directory=True)
    else:
        os.link(outside, payload / "link")
    with pytest.raises((ValueError, OSError)):
        builder.read_source(source)


def test_changed_payload_cannot_keep_an_old_inventory():
    manifest, _ = builder.read_source(ROOT / "modules/notes")
    data = builder.build_archive(manifest, {"note.txt": b"original"})
    changed = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(changed, "w") as target:
        for item in source.infolist():
            target.writestr(item, b"changed" if item.filename == "note.txt" else source.read(item))
    with pytest.raises(Failure):
        inspect_archive(changed.getvalue())


def test_output_needs_a_new_version_when_bytes_change(tmp_path):
    manifest, _ = builder.read_source(ROOT / "modules/notes")
    first = builder.publish(manifest, {"data.txt": b"a"}, tmp_path)
    expected = first.read_bytes()
    with pytest.raises(ValueError):
        builder.publish(copy.deepcopy(manifest), {"data.txt": b"b"}, tmp_path)
    assert first.read_bytes() == expected


def test_python_example_with_real_isolated_processes(tmp_path):
    manifest, files = examples.example("python", tmp_path / "cache", False, "node")
    path = builder.publish(manifest, files, tmp_path / "packages")
    assert conformance.check_package(path, sys.executable, "node") == 20
