# SPDX-License-Identifier: Apache-2.0
"""Verify AMD sysfs observations, mixed GPU collection, and bounded helper samples."""

import sys
import time
from pathlib import Path

import pytest
from ficc_node import collect, gpu_amd

from ficc.schema import Sample

AMD_VALUES = {"mem_info_vram_total": "8589934592", "mem_info_vram_used": "1073741824",
              "gpu_busy_percent": "37", "temp1_input": "42500"}


@pytest.fixture
def drm(tmp_path, monkeypatch):
    root = tmp_path / "drm"
    root.mkdir()
    devices = tmp_path / "devices"
    devices.mkdir()
    drivers = tmp_path / "drivers"
    drivers.mkdir()
    for name in ("amdgpu", "nvidia", "i915"):
        (drivers / name).mkdir()
    monkeypatch.setattr(gpu_amd, "DRM_ROOT", root)
    monkeypatch.setattr(collect.shutil, "which", lambda name: None)

    def add(card="card10", identity="0000:02:00.0", driver="amdgpu", values=None, monitor="amdgpu"):
        device = devices / identity
        if not device.exists():
            device.mkdir()
            (device / "driver").symlink_to(drivers / driver)
            hwmon = device / "hwmon" / "hwmon12"
            hwmon.mkdir(parents=True)
            (hwmon / "name").write_text(monitor + "\n")
            for key, value in (AMD_VALUES if values is None else values).items():
                path = hwmon / key if key == "temp1_input" else device / key
                path.write_text(value + "\n")
        card_path = root / card
        card_path.mkdir()
        (card_path / "device").symlink_to(device)
        return device

    return root, add


def nvidia_program(tmp_path, monkeypatch, source):
    program = tmp_path / "nvidia-smi"
    program.write_text(f"#!{sys.executable}\n" + source + "\n")
    program.chmod(0o700)
    monkeypatch.setattr(collect.shutil, "which", lambda name: str(program))
    return program


def test_amd_units_full_card_names_driver_filter_and_device_deduplication(drm):
    _, add = drm
    add()
    add("card11")
    add("card10-DP-1")
    add("renderD128")
    add("card2", "0000:03:00.0", driver="i915")
    rows, status = collect.gpu_metrics()
    assert status == "available"
    assert rows == [{"uuid": "AMD-PCI-0000:02:00.0", "name": "AMD GPU (amdgpu)",
                     "memory_total_bytes": 8589934592, "memory_used_bytes": 1073741824,
                     "utilization_percent": 37, "temperature_c": 42.5}]


def test_optional_product_name_and_temperature_driver_match(drm):
    _, add = drm
    device = add(values={**AMD_VALUES, "product_name": "AMD Example Product"}, monitor="other")
    row = gpu_amd.metrics()[0][0]
    assert row["name"] == "AMD Example Product" and row["temperature_c"] is None
    (device / "product_name").write_text("x" * 257)
    assert gpu_amd.metrics()[0][0]["name"] == "AMD GPU (amdgpu)"
    (device / "product_name").write_bytes(b"invalid\x00name")
    assert gpu_amd.metrics()[0][0]["name"] == "AMD GPU (amdgpu)"


@pytest.mark.parametrize("attribute,bad", [
    ("mem_info_vram_total", "NaN"), ("mem_info_vram_total", "-1"),
    ("mem_info_vram_used", "inf"), ("mem_info_vram_used", str(2**63)),
    ("mem_info_vram_used", "8589934593"), ("mem_info_vram_total", "1" * 65),
    ("gpu_busy_percent", "101"), ("gpu_busy_percent", "-1"), ("gpu_busy_percent", "12.5"),
    ("temp1_input", "-100001"), ("temp1_input", "300001"), ("temp1_input", "temperature=42"),
])
def test_malformed_or_out_of_range_readings_remain_independently_unknown(drm, attribute, bad):
    _, add = drm
    add(values={**AMD_VALUES, attribute: bad})
    row = gpu_amd.metrics()[0][0]
    wire = {"mem_info_vram_total": "memory_total_bytes", "mem_info_vram_used": "memory_used_bytes",
            "gpu_busy_percent": "utilization_percent", "temp1_input": "temperature_c"}
    expected = {"memory_total_bytes": 8589934592, "memory_used_bytes": 1073741824,
                "utilization_percent": 37, "temperature_c": 42.5}
    expected[wire[attribute]] = None
    assert {key: row[key] for key in expected} == expected


def test_missing_and_unreadable_attributes_do_not_hide_gpu_or_other_readings(drm, monkeypatch):
    _, add = drm
    device = add()
    (device / "gpu_busy_percent").unlink()
    original = Path.open

    def opened(path, mode="r", *args, **kwargs):
        assert mode == "rb", "Collector attempted a write or unbounded text read."
        if path.name == "mem_info_vram_used":
            raise PermissionError("Test attribute is unreadable.")
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", opened)
    rows, status = gpu_amd.metrics()
    assert status == "available" and len(rows) == 1
    assert rows[0]["memory_used_bytes"] is None and rows[0]["utilization_percent"] is None
    assert rows[0]["memory_total_bytes"] == 8589934592 and rows[0]["temperature_c"] == 42.5


def test_all_missing_measurements_remain_null(drm):
    _, add = drm
    add(values={})
    rows, status = gpu_amd.metrics()
    assert status == "available" and len(rows) == 1
    assert all(value is None for key, value in rows[0].items() if key not in {"uuid", "name"})


def test_gpu_absence_and_discovery_failure_have_distinct_status(drm, monkeypatch):
    root, _ = drm
    assert collect.gpu_metrics() == ([], "unsupported")
    monkeypatch.setattr(gpu_amd, "DRM_ROOT", root / "missing")
    assert collect.gpu_metrics() == ([], "unsupported")
    monkeypatch.setattr(gpu_amd, "DRM_ROOT", root)
    original = Path.iterdir

    def listing(path):
        if path == root:
            raise PermissionError("Test DRM catalogue is unreadable.")
        return original(path)

    monkeypatch.setattr(Path, "iterdir", listing)
    assert collect.gpu_metrics() == ([], "unavailable")


def test_mixed_real_query_and_live_linux_sample_keep_wire_compatibility(drm, tmp_path, monkeypatch):
    _, add = drm
    add()
    nvidia_program(tmp_path, monkeypatch,
                   'print("GPU-example, Example NVIDIA, 8192, 1024, 25, 39")')
    value = collect.collect()
    Sample.model_validate(value)
    rows = value["resources"]["gpus"]
    assert [row["uuid"] for row in rows] == ["GPU-example", "AMD-PCI-0000:02:00.0"]
    assert rows[0]["memory_total_bytes"] == 8192 * 1048576
    assert rows[0]["memory_used_bytes"] == 1024 * 1048576
    assert value["capabilities"]["gpu_source"] == "nvidia-smi+amdgpu-sysfs"
    assert value["capabilities"]["gpu_metrics"] is True


@pytest.mark.parametrize("source", ["raise SystemExit(1)", "print('malformed')", "print('x' * 65537)"])
def test_failed_nvidia_query_does_not_hide_amd(drm, tmp_path, monkeypatch, source):
    _, add = drm
    add()
    nvidia_program(tmp_path, monkeypatch, source)
    rows, status = collect.gpu_metrics()
    assert status == "available" and [row["uuid"] for row in rows] == ["AMD-PCI-0000:02:00.0"]


def test_unlaunchable_nvidia_query_does_not_hide_amd(drm, tmp_path, monkeypatch):
    _, add = drm
    add()
    monkeypatch.setattr(collect.shutil, "which", lambda name: str(tmp_path / "missing-nvidia-smi"))
    rows, status = collect.gpu_metrics()
    assert status == "available" and rows[0]["uuid"].startswith("AMD-PCI-")


def test_nvidia_timeout_is_bounded_and_retains_amd(drm, tmp_path, monkeypatch):
    _, add = drm
    add()
    nvidia_program(tmp_path, monkeypatch, "import time\ntime.sleep(60)")
    started = time.monotonic()
    rows, status = collect.gpu_metrics()
    elapsed = time.monotonic() - started
    assert 2.5 <= elapsed < 7
    assert status == "available" and rows[0]["uuid"].startswith("AMD-PCI-")


def test_nonfinite_nvidia_metrics_do_not_poison_mixed_sample(drm, tmp_path, monkeypatch):
    _, add = drm
    add()
    nvidia_program(tmp_path, monkeypatch, 'print("GPU-example, Example NVIDIA, nan, inf, 101, -101")')
    value = collect.collect()
    Sample.model_validate(value)
    row = value["resources"]["gpus"][0]
    assert all(value is None for key, value in row.items() if key not in {"uuid", "name"})
    assert value["resources"]["gpus"][1]["temperature_c"] == 42.5


def test_combined_and_amd_only_catalogues_remain_within_wire_limit(drm, tmp_path, monkeypatch):
    _, add = drm
    for index in range(70):
        add(f"card{index}", f"0000:{index:02x}:00.0")
    amd, status = collect.gpu_metrics()
    assert status == "available" and len(amd) == 64
    assert amd[0]["uuid"] == "AMD-PCI-0000:00:00.0" and amd[-1]["uuid"] == "AMD-PCI-0000:3f:00.0"
    nvidia_program(tmp_path, monkeypatch, 'print("GPU-example, Example NVIDIA, 8192, 1024, 25, 39")')
    value = collect.collect()
    Sample.model_validate(value)
    rows = value["resources"]["gpus"]
    assert len(rows) == 64 and rows[0]["uuid"] == "GPU-example"
    assert rows[-1]["uuid"] == "AMD-PCI-0000:3e:00.0"
    assert value["capabilities"]["gpu_source"] == "nvidia-smi+amdgpu-sysfs"


def test_source_capability_reports_only_retained_gpu_sources(drm, tmp_path, monkeypatch):
    _, add = drm
    value = collect.collect()
    assert value["capabilities"]["gpu_source"] == "none"
    assert value["capabilities"]["gpu_metrics"] is False
    add()
    assert collect.collect()["capabilities"]["gpu_source"] == "amdgpu-sysfs"
    nvidia_program(tmp_path, monkeypatch,
                   '[print(f"GPU-{i}, Example NVIDIA, 8192, 1024, 25, 39") for i in range(64)]')
    value = collect.collect()
    Sample.model_validate(value)
    assert value["capabilities"]["gpu_source"] == "nvidia-smi"
    assert len(value["resources"]["gpus"]) == 64
