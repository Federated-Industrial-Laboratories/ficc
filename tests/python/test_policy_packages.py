# SPDX-License-Identifier: Apache-2.0
"""Qualify publisher signatures and exact archive coverage with distinct policy payloads."""

import hashlib
import io
import json
import struct
import tracemalloc
import zipfile

import pytest
from policy_fixtures import signed_pack

from ficc.policy_packages import inspect, verify


def changed(raw, name, data):
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as original, zipfile.ZipFile(output, "w") as rebuilt:
        for item in original.infolist():
            rebuilt.writestr(item, data if item.filename == name else original.read(item.filename))
        if name not in original.namelist():
            rebuilt.writestr(name, data)
    return output.getvalue()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_exact_signed_payloads_reject_tampering_and_undeclared_members(policy_material, tmp_path, count):
    for index in range(count):
        raw = signed_pack(tmp_path / f"package-{index}", policy_material["key"],
                          package_id=f"independent-{index}", extra={"fixture": index, "label": f"Dataset {index}"})
        value, fingerprint, payload = verify(raw, policy_material["public_key"])
        assert value["id"] == f"independent-{index}"
        assert fingerprint.startswith("SHA256:") and len(payload) == 3
        for name, replacement in (("payload/extra.json", b'{"fixture":-1}'),
                                  (f"payload/undeclared-{index}.rego", b"package outside\n"),
                                  ("manifest.sig", b"invalid signature")):
            with pytest.raises(ValueError):
                verify(changed(raw, name, replacement), policy_material["public_key"])
        value["publisher"] = "untrusted-publisher"
        with pytest.raises(ValueError, match="signature"):
            verify(changed(raw, "manifest.json", json.dumps(value).encode()), policy_material["public_key"])
        assert inspect(raw)[0]["id"] == f"independent-{index}"


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_archive_links_duplicates_and_path_escape_are_rejected(policy_material, count):
    raw = policy_material["managed"]
    for index in range(count):
        def declared(name, mode):
            manifest = inspect(raw)[0]
            payload = f"package qualified_{index}\n".encode()
            manifest["id"] = f"qualified-{index}"
            manifest["files"] = {name: hashlib.sha256(payload).hexdigest()}
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr("manifest.json", json.dumps(manifest))
                archive.writestr("manifest.sig", b"structural inspection fixture")
                item = zipfile.ZipInfo("payload/" + name)
                item.external_attr = mode << 16
                archive.writestr(item, payload)
            return output.getvalue()
        allowed = f"policy-{index}.rego"
        assert inspect(declared(allowed, 0o100600))[3] == {allowed: f"package qualified_{index}\n".encode()}
        with pytest.raises(ValueError, match="member set"):
            inspect(declared(allowed, 0o120777))
        with pytest.raises(ValueError, match="path"):
            inspect(declared(f"../escape-{index}.rego", 0o100600))
        output = io.BytesIO(raw)
        with pytest.warns(UserWarning, match="Duplicate name"):
            with zipfile.ZipFile(output, "a") as archive:
                archive.writestr("manifest.json", str(index).encode())
        with pytest.raises(ValueError, match="member set"):
            inspect(output.getvalue())


def test_understated_compressed_manifest_has_bounded_memory():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", b"x" * (16 * 1024 * 1024))
        archive.writestr("manifest.sig", b"invalid")
        archive.writestr("payload/policy.rego", b"package ficc")
    raw = bytearray(output.getvalue())
    # Both headers understate the expanded manifest, as an untrusted ZIP can do.
    struct.pack_into("<I", raw, 22, 128)
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<I", raw, central + 24, 128)
    tracemalloc.start()
    try:
        with pytest.raises(ValueError):
            inspect(bytes(raw))
        assert tracemalloc.get_traced_memory()[1] < 2 * 1024 * 1024
    finally:
        tracemalloc.stop()
