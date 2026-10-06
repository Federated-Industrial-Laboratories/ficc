# SPDX-License-Identifier: Apache-2.0
"""Read Linux counters and optional structured NVIDIA and AMD GPU metrics."""

import csv
import io
import math
import os
import selectors
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import VERSION
from .gpu_amd import metrics as amd_metrics


def read_text(path: str, maximum: int = 262144) -> str:
    with open(path, encoding="ascii", errors="replace") as stream:
        return stream.read(maximum)


def cpu_ticks() -> tuple[int, int]:
    values = [int(v) for v in read_text("/proc/stat").splitlines()[0].split()[1:9]]
    return sum(values), values[3] + values[4]


def nvidia_metrics() -> tuple[list[dict], str]:
    executable = shutil.which("nvidia-smi")
    if executable is None:
        return [], "unsupported"
    command = [executable, "--query-gpu=uuid,name,memory.total,memory.used,utilization.gpu,temperature.gpu",
               "--format=csv,noheader,nounits"]
    output = bytearray()
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return [], "unavailable"
    assert process.stdout is not None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 3
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise ValueError("GPU query timed out.")
                for key, _ in selector.select(0.1):
                    block = os.read(key.fd, 8192)
                    if not block:
                        selector.unregister(key.fileobj)
                    output.extend(block)
                    if len(output) > 65536:
                        raise ValueError("GPU output exceeds the limit.")
        if process.wait(timeout=1) != 0:
            return [], "unavailable"
        rows = list(csv.reader(io.StringIO(output.decode("utf-8"))))
        if len(rows) > 64:
            return [], "unavailable"
        metrics = []
        for row in rows:
            if len(row) != 6:
                raise ValueError("GPU response is invalid.")
            uuid, name, total, used, utilization, temperature = [v.strip() for v in row]
            if any(not value or len(value) > 256 or not value.isprintable() for value in (uuid, name)):
                raise ValueError("GPU identity is invalid.")
            def number(value: str, multiplier: int = 1, minimum: float = 0,
                       maximum: float = 2**63 - 1) -> float | None:
                try:
                    result = float(value) * multiplier
                    return result if math.isfinite(result) and minimum <= result <= maximum else None
                except ValueError:
                    return None
            metrics.append({"uuid": uuid, "name": name,
                            "memory_total_bytes": number(total, 1048576),
                            "memory_used_bytes": number(used, 1048576),
                            "utilization_percent": number(utilization, maximum=100),
                            "temperature_c": number(temperature, minimum=-100, maximum=300)})
        return metrics, "available" if metrics else "unsupported"
    except (ValueError, OSError, UnicodeError, subprocess.TimeoutExpired):
        return [], "unavailable"
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout:
            process.stdout.close()


def gpu_metrics() -> tuple[list[dict], str]:
    nvidia, nvidia_status = nvidia_metrics()
    amd, amd_status = amd_metrics()
    metrics = (nvidia + amd)[:64]
    if metrics:
        return metrics, "available"
    return [], "unavailable" if "unavailable" in {nvidia_status, amd_status} else "unsupported"


def collect() -> dict:
    if sys.platform == "darwin":
        from .collect_macos import collect as collect_native
        return collect_native()
    first_total, first_idle = cpu_ticks()
    time.sleep(0.1)
    total, idle = cpu_ticks()
    delta = total - first_total
    percent = 100 * (1 - (idle - first_idle) / delta) if delta > 0 else None
    memory = {}
    for line in read_text("/proc/meminfo").splitlines():
        name, value = line.split(":", 1)
        memory[name] = int(value.split()[0]) * 1024
    network = []
    for line in read_text("/proc/net/dev").splitlines()[2:66]:
        name, values = line.split(":", 1)
        fields = values.split()
        network.append({"name": name.strip(), "rx_bytes": int(fields[0]), "tx_bytes": int(fields[8])})
    disk = os.statvfs("/")
    gpus, gpu_status = gpu_metrics()
    gpu_sources = dict.fromkeys("amdgpu-sysfs" if item["uuid"].startswith("AMD-PCI-") else "nvidia-smi"
                                for item in gpus)
    return {
        "version": "1",
        "boot_id": read_text("/proc/sys/kernel/random/boot_id", 128).strip(),
        "observed_at": time.time(), "monotonic_seconds": time.monotonic(),
        "capabilities": {"resources": True, "gpu_metrics": gpu_status == "available",
                         "jobs": False, "files": False, "terminals": False,
                         "source": "linux-procfs", "gpu_source": "+".join(gpu_sources) or "none"},
        "resources": {
            "cpu_percent": percent, "cpu_count": os.cpu_count() or 1,
            "load": list(os.getloadavg()),
            "memory_total_bytes": memory["MemTotal"],
            "memory_available_bytes": memory.get("MemAvailable", memory.get("MemFree", 0)),
            "uptime_seconds": float(read_text("/proc/uptime", 128).split()[0]),
            "storage": [{"mount": "/", "total_bytes": disk.f_blocks * disk.f_frsize,
                         "available_bytes": disk.f_bavail * disk.f_frsize}],
            "network": network, "gpus": gpus, "gpu_status": gpu_status,
        },
        "helper_version": VERSION,
        "python_version": str(Path(os.__file__).parent.name),
    }
