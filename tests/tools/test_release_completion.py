# SPDX-License-Identifier: Apache-2.0
"""Require the original complete release and every byte of the native payload."""

import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from finalize_release import finalize, required_artifacts  # noqa: E402
from release_lib.common import digest, write_json  # noqa: E402


def release(tmp_path, count=1, corrupt=False):
    output = tmp_path / "release"
    output.mkdir()
    bodies = {f"module-{i}.py": f"distinct runtime {i}".encode() for i in range(count)}
    manifest = {"files": {name: hashlib.sha256(value).hexdigest() for name, value in bodies.items()}, "links": {}}
    for name in required_artifacts("1.0.0"):
        (output / name).write_text("original artifact " + name)
    artifacts = {p.name: digest(p) for p in output.iterdir()}
    write_json(output / "build.json", {"version": "1.0.0", "payload_manifest": manifest, "artifacts": artifacts})
    (output / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in sorted(output.iterdir()) if p.is_file()))
    if corrupt:
        bodies[f"module-{count - 1}.py"] = b"changed last runtime member"
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        for name, body in {"bundle.json": json.dumps(manifest).encode(), **bodies}.items():
            item = tarfile.TarInfo("opt/ficc/" + name)
            item.size = len(body)
            archive.addfile(item, io.BytesIO(body))
    package = tmp_path / "ficc-bin-1.0.0-1-x86_64.pkg.tar.zst"
    package.write_bytes(subprocess.check_output(["zstd", "-q", "-c"], input=data.getvalue()))
    return output, package


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("corrupt", [False, True])
def test_arch_finalization_checks_every_payload_member(tmp_path, count, corrupt):
    output, package = release(tmp_path, count, corrupt)
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    if corrupt:
        with pytest.raises(ValueError, match="files differ"):
            finalize(output, package)
        assert {p.name: p.read_bytes() for p in output.iterdir()} == before
    else:
        finalize(output, package)
        build = json.loads((output / "build.json").read_text())
        assert build["formats_complete"] is True
        assert set(build["artifacts"]) == required_artifacts("1.0.0") | {package.name}
        assert build["artifacts"] == {name: digest(output / name) for name in build["artifacts"]}


@pytest.mark.parametrize("name", sorted(required_artifacts("1.0.0")))
@pytest.mark.parametrize("change", ["missing", "changed", "unbound"])
def test_incomplete_or_changed_release_is_not_certified(tmp_path, name, change):
    output, package = release(tmp_path)
    if change == "missing":
        (output / name).unlink()
    elif change == "changed":
        (output / name).write_text("changed artifact")
    else:
        build = json.loads((output / "build.json").read_text())
        del build["artifacts"][name]
        write_json(output / "build.json", build)
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    with pytest.raises(ValueError):
        finalize(output, package)
    assert {p.name: p.read_bytes() for p in output.iterdir()} == before
