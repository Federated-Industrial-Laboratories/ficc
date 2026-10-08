# SPDX-License-Identifier: Apache-2.0
"""Check Apple unified-memory observations and bounded metric commands."""

import plistlib
import subprocess
import sys

import pytest
from ficc_node import gpu, gpu_apple
from ficc_node.metric_command import read_command

from ficc.schema import GPU


def apple_entry(index=0):
    return {"IORegistryEntryID": 100 + index, "model": b"Apple M4\0",
            "PerformanceStatistics": {"Device Utilization %": 12, "In use system memory": 123456,
                                      "Alloc system memory": 999999}}


@pytest.mark.parametrize("count", [1, 64])
def test_apple_unified_memory_is_not_dedicated_capacity(monkeypatch, count):
    def query(command, **kwargs):
        assert command == ["/usr/sbin/ioreg", "-a", "-r", "-d", "1", "-c", "AGXAccelerator"]
        assert kwargs["maximum"] == 1048576
        return plistlib.dumps([apple_entry(index) for index in range(count)])
    monkeypatch.setattr(gpu_apple, "read_command", query)
    monkeypatch.setattr(gpu.platform, "system", lambda: "Darwin")
    metrics, status = gpu.gpu_metrics()
    assert len(metrics) == count and status == "available"
    for item in metrics:
        parsed = GPU.model_validate(item)
        assert parsed.name == "Apple M4" and parsed.memory_kind == "unified"
        assert parsed.memory_used_bytes == 123456
        assert parsed.utilization_percent == 12
        assert parsed.memory_total_bytes is parsed.temperature_c is None
        assert parsed.reservation_supported is False


@pytest.mark.parametrize("stats", [{}, {"Device Utilization %": "NaN", "In use system memory": -1}, []])
def test_apple_unknown_readings_are_not_zero(monkeypatch, stats):
    entry = {**apple_entry(), "PerformanceStatistics": stats}
    monkeypatch.setattr(gpu_apple, "read_command", lambda *a, **k: plistlib.dumps([entry]))
    metrics, status = gpu_apple.apple_metrics()
    assert status == "unavailable" and len(metrics) == 1
    assert metrics[0]["utilization_percent"] is metrics[0]["memory_used_bytes"] is None


@pytest.mark.parametrize("raw", [b"", b"<plist><array>", plistlib.dumps({}),
                                  plistlib.dumps([{}]), plistlib.dumps([apple_entry()] * 65)])
def test_apple_malformed_or_oversized_registry_is_unavailable(monkeypatch, raw):
    monkeypatch.setattr(gpu_apple, "read_command", lambda *a, **k: raw)
    assert gpu_apple.apple_metrics() == ([], "unavailable")


def test_apple_no_devices_and_failed_query_are_distinct(monkeypatch):
    monkeypatch.setattr(gpu_apple, "read_command", lambda *a, **k: plistlib.dumps([]))
    assert gpu_apple.apple_metrics() == ([], "unsupported")
    def failed(*args, **kwargs):
        raise subprocess.TimeoutExpired("ioreg", 3)
    monkeypatch.setattr(gpu_apple, "read_command", failed)
    assert gpu_apple.apple_metrics() == ([], "unavailable")


def test_metric_command_enforces_output_deadline_exit_and_stdin():
    assert read_command([sys.executable, "-c", "import sys; print(len(sys.stdin.read()))"]) == b"0\n"
    with pytest.raises(ValueError, match="limit"):
        read_command([sys.executable, "-c", "print('x' * 8192)"], maximum=1024)
    with pytest.raises(ValueError, match="timed out"):
        read_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1)
    with pytest.raises((subprocess.TimeoutExpired, ValueError)):
        read_command([sys.executable, "-c", "import os,time; os.close(1); time.sleep(5)"], timeout=0.1)
    with pytest.raises(ValueError, match="failed"):
        read_command([sys.executable, "-c", "raise SystemExit(1)"])


@pytest.mark.parametrize("identity", [True, -1, 2**64, "100"])
def test_apple_invalid_identity_is_unavailable(monkeypatch, identity):
    monkeypatch.setattr(gpu_apple, "read_command", lambda *a, **k:
                        plistlib.dumps([{**apple_entry(), "IORegistryEntryID": identity}]))
    assert gpu_apple.apple_metrics() == ([], "unavailable")


@pytest.mark.parametrize("stats,expected_status", [({}, "unavailable"),
    ({"Device Utilization %": 0, "In use system memory": 4096}, "available")])
def test_macos_resource_sample_includes_apple_observations(monkeypatch, stats, expected_status):
    from ficc_node import collect_macos

    from ficc.schema import Sample

    monkeypatch.setattr(gpu.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(gpu_apple, "read_command", lambda *a, **k:
                        plistlib.dumps([{**apple_entry(), "PerformanceStatistics": stats}]))
    ticks = iter([(100, 50), (200, 125)])
    monkeypatch.setattr(collect_macos, "cpu_ticks", lambda: next(ticks))
    monkeypatch.setattr(collect_macos.time, "sleep", lambda _: None)
    outputs = {"hw.memsize": str(16 * 1024**3),
               "kern.boottime": "{ sec = 1, usec = 0 }",
               "kern.bootsessionuuid": "00000000-0000-0000-0000-000000000001",
               "/usr/bin/vm_stat": "page size of 16384 bytes\nPages free: 1.\nPages inactive: 2.\nPages speculative: 3.",
               "-ibn": "lo0 16384 <Link#1> 0 0 0 0 0 0 0"}
    monkeypatch.setattr(collect_macos, "command", lambda *args: outputs[args[-1]])
    value = collect_macos.collect()
    Sample.model_validate(value)
    assert value["capabilities"]["gpu_metrics"] is (expected_status == "available")
    assert value["capabilities"]["gpu_source"] == "apple-ioreg"
    assert value["resources"]["gpu_status"] == expected_status
    assert value["resources"]["gpus"][0]["memory_total_bytes"] is None
    assert value["resources"]["cpu_percent"] == 25


def test_legacy_nvidia_sample_retains_reservation_eligibility():
    parsed = GPU.model_validate({"uuid": "GPU-example", "name": "Example NVIDIA",
        "memory_total_bytes": 4096, "memory_used_bytes": 0,
        "utilization_percent": 0, "temperature_c": None})
    assert parsed.reservation_supported is True
    assert parsed.source == parsed.memory_kind == "unknown"
