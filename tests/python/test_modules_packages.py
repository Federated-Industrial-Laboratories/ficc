# SPDX-License-Identifier: Apache-2.0
"""Exercise module inventory, extraction and declarative validation boundaries."""

import copy
import hashlib
import io
import json
import os
import stat
import zipfile

import pytest

from ficc.errors import Failure
from ficc.modules import inspect_archive
from ficc.modules.archive import publish, verify
from ficc.modules.manifest import validate_manifest, validate_parameters


def package(files=None, **changes):
    files = {"notes.txt": b"example"} if files is None else files
    manifest = {
        "format_version": 1, "id": "org.example.demo", "version": "1.0.0",
        "category": "productivity", "contract_version": 1, "host_api": 1,
        "runtime": {"kind": "declarative", "language": "none"},
        "capabilities": [], "dependencies": [], "actions": [],
        "ui": {"type": "column", "children": [{"type": "clock"}]},
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    }
    manifest.update(changes)
    return manifest, files


def bundle(manifest, files, extra=()):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, data in [*files.items(), *extra]:
            archive.writestr(name, data)
    return output.getvalue()


@pytest.mark.parametrize("count", [1, 64])
def test_complete_private_inventory_roundtrip(tmp_path, count):
    manifest, files = package({f"data/item-{i}.txt": str(i).encode() for i in range(count)})
    inspection = inspect_archive(bundle(manifest, files))
    assert inspection.manifest == manifest
    exposed = inspection.manifest
    exposed["id"] = "changed"
    assert inspection.manifest["id"] == manifest["id"]
    directory = publish(tmp_path, inspection)
    verify(directory, manifest, inspection._manifest)
    assert publish(tmp_path, inspection) == directory
    assert stat.S_IMODE(directory.stat().st_mode) == 0o500
    assert all(stat.S_IMODE((directory / name).stat().st_mode) == 0o400 for name in files)


@pytest.mark.parametrize("name", ["../escape", "/tmp/escape", "a/../../escape", "a\\b", "a./b", "a//b"])
def test_reject_path_escape(name):
    manifest, files = package()
    with pytest.raises(Failure):
        inspect_archive(bundle(manifest, files, [(name, b"bad")]))


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK])
def test_reject_nonregular_members(mode):
    manifest, files = package()
    member = zipfile.ZipInfo("linked")
    member.create_system = 3
    member.external_attr = (mode | 0o600) << 16
    with pytest.raises(Failure):
        inspect_archive(bundle(manifest, files, [(member, b"notes.txt")]))


@pytest.mark.parametrize("case", ["extra", "missing", "digest", "case", "prefix", "duplicate", "directory"])
def test_reject_incomplete_or_ambiguous_inventory(case):
    manifest, files = package()
    extra = []
    if case == "extra":
        extra = [("unlisted", b"bad")]
    elif case == "missing":
        files = {}
    elif case == "digest":
        files["notes.txt"] = b"changed"
    elif case == "case":
        extra = [("NOTES.txt", b"example")]
    elif case == "prefix":
        manifest, files = package({"a": b"a", "a/b": b"b"})
    elif case == "duplicate":
        extra = [("notes.txt", b"example")]
    else:
        extra = [("empty/", b"")]
    with pytest.raises(Failure):
        inspect_archive(bundle(manifest, files, extra))


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "writable", "extra-dir", "changed"])
def test_detect_installed_package_tampering(tmp_path, kind):
    manifest, files = package()
    inspection = inspect_archive(bundle(manifest, files))
    directory = publish(tmp_path, inspection)
    directory.chmod(0o700)
    target = directory / "notes.txt"
    if kind == "symlink":
        target.unlink()
        target.symlink_to(tmp_path / "outside")
    elif kind == "hardlink":
        os.link(target, tmp_path / "linked")
    elif kind == "extra-dir":
        (directory / "unknown").mkdir(mode=0o500)
    else:
        target.chmod(0o600)
        if kind == "changed":
            target.write_bytes(b"changed")
            target.chmod(0o400)
    directory.chmod(0o500)
    with pytest.raises((Failure, OSError)):
        verify(directory, manifest, inspection._manifest)


@pytest.mark.parametrize("change", [
    {"host_api": True}, {"format_version": 2}, {"extra": "unknown"},
    {"dependencies": ["network-package"]}, {"runtime": {"kind": [], "language": "none"}},
    {"ui": {"type": "column", "html": "<script>bad</script>"}},
    {"ui": {"type": "column", "children": [{"type": "audio-player", "ref": "https://host"}]}},
    {"ui": {"type": "column", "children": [{"type": "button", "action": "undeclared"}]}},
])
def test_reject_unsupported_manifest_contract(change):
    manifest, _ = package(**copy.deepcopy(change))
    with pytest.raises(Failure):
        validate_manifest(manifest)


def test_entrypoint_must_be_inventory_member_and_native_private_executable(tmp_path):
    runtime = {"kind": "native", "language": "rust", "platform": "linux",
               "architecture": "x86_64", "entry": "program"}
    manifest, files = package(runtime=runtime)
    with pytest.raises(Failure):
        validate_manifest(manifest)
    manifest, files = package({"program": b"not executed"}, runtime=runtime)
    inspection = inspect_archive(bundle(manifest, files))
    directory = publish(tmp_path, inspection)
    assert stat.S_IMODE((directory / "program").stat().st_mode) == 0o500
    verify(directory, manifest, inspection._manifest)


def test_parameter_bounds_do_not_accept_booleans_unknown_fields_or_huge_numbers():
    schema = {"count": {"type": "integer", "required": True, "min": 1, "max": 64}}
    assert validate_parameters(schema, {"count": 64}) == {"count": 64}
    for values in ({}, {"count": True}, {"count": 0}, {"count": 65}, {"count": 10**500},
                   {"count": 1, "shell": "unsafe"}):
        with pytest.raises(Failure):
            validate_parameters(schema, values)


@pytest.mark.parametrize("limit,value", [("MAX_ARCHIVE", 1), ("MAX_MEMBERS", 1),
                                          ("MAX_EXPANDED", 100), ("MAX_FILE", 1000)])
def test_archive_limits_apply_before_publication(monkeypatch, limit, value):
    import ficc.modules.archive as module

    data = bundle(*package({"data.txt": b"x" * 2000}))
    monkeypatch.setattr(module, limit, value)
    with pytest.raises(Failure):
        inspect_archive(data)


def test_encrypted_members_and_duplicate_manifest_keys_are_rejected():
    data = bytearray(bundle(*package()))
    directory = data.index(b"PK\x01\x02")
    data[directory + 8] |= 1
    with pytest.raises(Failure):
        inspect_archive(bytes(data))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("manifest.json", '{"format_version":1,"format_version":2}')
    with pytest.raises(Failure):
        inspect_archive(output.getvalue())


@pytest.mark.parametrize("kind,required", [
    ("editor", ["workspace:read", "workspace:write"]),
    ("audio-player", ["workspace:read", "workspace:write", "audio:playback"]),
])
def test_host_components_require_complete_declared_capabilities(kind, required):
    ui = {"type": "column", "children": [{"type": "group", "children": [{"type": kind}]}]}
    for grants in ([], *[required[:index] + required[index + 1:] for index in range(len(required))]):
        manifest, _ = package(ui=ui, capabilities=grants)
        with pytest.raises(Failure):
            validate_manifest(manifest)
    manifest, _ = package(ui=ui, capabilities=required)
    assert validate_manifest(manifest) == manifest
