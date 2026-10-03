# SPDX-License-Identifier: Apache-2.0
"""Keep a working package and its grants when replacement admission fails."""

import platform
import shutil
import struct
import subprocess

import pytest
from test_modules_packages import bundle, package
from test_workspaces import installed

from ficc.errors import Failure
from ficc.modules.sandbox import SandboxStatus


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("case", ["architecture", "platform", "interpreter", "sandbox"])
def test_refused_replacement_preserves_active_package(console, monkeypatch, count, case):
    import ficc.modules.sandbox as sandbox

    client, service = console
    spaces = [client.post("/api/v1/workspaces", json={"name": f"Workspace {i}"}).json()["id"]
              for i in range(count)]
    first = installed(client, spaces, ["workspace:read"])
    original = service.modules.get(first)
    runtime = {"kind": "python", "language": "python", "platform": "linux",
               "architecture": "any", "entry": "main.py"}
    if case == "architecture":
        monkeypatch.setattr(sandbox.platform, "machine", lambda: "x86_64")
        runtime.update(kind="native", language="c", architecture="aarch64")
    elif case == "platform":
        monkeypatch.setattr(sandbox.platform, "system", lambda: "Other")
    elif case == "interpreter":
        access = sandbox.os.access
        monkeypatch.setattr(sandbox.os, "access", lambda path, mode: False if path == "/usr/bin/node" else access(path, mode))
        runtime.update(kind="javascript", language="javascript")
    raw = bundle(*package({"main.py": b"This payload must never run."}, version="2.0.0",
                          runtime=runtime, capabilities=["workspace:read"]))
    preview = client.post("/api/v1/module-install-previews", content=raw).json()
    result = client.post("/api/v1/modules", json={"preview_id": preview["preview_id"],
        "digest": preview["digest"], "accept_unverified": True})
    assert result.status_code == 201, result.text
    replacement = result.json()
    probes = []

    async def probe():
        probes.append(True)
        assert case == "sandbox", "Incompatible package reached sandbox admission"
        return SandboxStatus(False, "Unavailable host controls")

    monkeypatch.setattr(service.module_runtime.sandbox, "probe", probe)
    grants = [{"capability": "workspace:read", "target_ids": spaces}]
    result = client.post(f"/api/v1/modules/{replacement['digest']}/activation",
                         json={"enabled": True, "grants": grants})
    assert result.status_code == (503 if case in {"interpreter", "sandbox"} else 409)
    assert result.json()["error"]["code"] == ("module_sandbox_unavailable" if case == "sandbox"
                                               else "module_runtime_unavailable")
    assert probes == ([True] if case == "sandbox" else [])
    assert service.modules.get(first) == original
    assert service.modules.get(replacement["digest"]) == replacement
    assert not service.module_runtime.active
    if case != "sandbox":
        with pytest.raises(Failure) as error:
            service.modules.set_enabled(replacement["digest"], True, grants, sandbox_ready=True)
        assert error.value.code == "module_runtime_unavailable"
        assert service.modules.get(first) == original
        assert service.modules.get(replacement["digest"]) == replacement


@pytest.fixture
def native_entry(tmp_path):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("A C compiler is required for native activation checks.")

    def build(loader=None):
        output = tmp_path / "program"
        command = [compiler, "-x", "c", "-", "-o", str(output)]
        if loader:
            command.append("-Wl,--dynamic-linker=" + loader)
        subprocess.run(command, input="int main(void) { return 0; }\n", text=True,
                       check=True, capture_output=True, timeout=30)
        return output.read_bytes()

    return build


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("missing", [False, True])
def test_native_loader_admission_preserves_or_replaces_exact_grants(
        console, monkeypatch, native_entry, count, missing):
    client, service = console
    spaces = [client.post("/api/v1/workspaces", json={"name": f"Native workspace {i}"}).json()["id"]
              for i in range(count)]
    first = installed(client, spaces, ["workspace:read"])
    original = service.modules.get(first)
    data = native_entry("/lib/ficc-test-unavailable-loader.so" if missing else None)
    runtime = {"kind": "native", "language": "c", "platform": "linux",
               "architecture": platform.machine(), "entry": "program"}
    raw = bundle(*package({"program": data}, version="2.0.0", runtime=runtime,
                          capabilities=["workspace:read"]))
    preview = client.post("/api/v1/module-install-previews", content=raw).json()
    response = client.post("/api/v1/modules", json={"preview_id": preview["preview_id"],
        "digest": preview["digest"], "accept_unverified": True})
    assert response.status_code == 201
    replacement = response.json()
    probes = []

    async def probe():
        probes.append(True)
        assert not missing, "A missing native loader reached sandbox admission"
        return SandboxStatus(True, "Available")

    monkeypatch.setattr(service.module_runtime.sandbox, "probe", probe)
    grants = [{"capability": "workspace:read", "target_ids": spaces}]
    result = client.post(f"/api/v1/modules/{replacement['digest']}/activation",
                         json={"enabled": True, "grants": grants})
    if missing:
        assert result.status_code == 503
        assert result.json()["error"]["code"] == "module_runtime_unavailable"
        assert "loader" in result.json()["error"]["message"]
        assert service.modules.get(first) == original
        assert service.modules.get(replacement["digest"]) == replacement
        with pytest.raises(Failure, match="loader"):
            service.modules.set_enabled(replacement["digest"], True, grants, sandbox_ready=True)
        assert service.modules.get(first) == original
        assert service.modules.get(replacement["digest"]) == replacement
        assert probes == []
    else:
        assert result.status_code == 200, result.text
        assert not service.modules.get(first)["enabled"]
        assert service.modules.get(first)["grants"] == []
        assert result.json()["enabled"]
        service.modules.require(replacement["digest"], "workspace:read", spaces)
        assert probes == [True]


@pytest.mark.parametrize("case", ["not-elf", "architecture", "header-table", "segment", "loader-path"])
def test_native_header_admission_refuses_invalid_or_hidden_runtime(tmp_path, native_entry, case):
    from ficc.modules.native import require_native

    data = bytearray(native_entry("/tmp/ficc-hidden-loader" if case == "loader-path" else None))
    if case == "not-elf":
        data[:4] = b"text"
    elif case == "architecture":
        struct.pack_into("<H", data, 18, 0)
    elif case == "header-table":
        struct.pack_into("<Q", data, 32, len(data))
    elif case == "segment":
        table = struct.unpack_from("<Q", data, 32)[0]
        struct.pack_into("<Q", data, table + 8, len(data) + 1)
    (tmp_path / "program").write_bytes(data)
    with pytest.raises(Failure) as error:
        require_native(tmp_path, {"entry": "program", "architecture": platform.machine()})
    assert error.value.code == "module_runtime_unavailable"
