# SPDX-License-Identifier: Apache-2.0
"""Read Linux counters and optional structured NVIDIA and AMD GPU metrics."""

import os
import sys
import time
from pathlib import Path

from . import VERSION
from .gpu import gpu_metrics


def read_text(path: str, maximum: int = 262144) -> str:
    with open(path, encoding="ascii", errors="replace") as stream:
        return stream.read(maximum)


def cpu_ticks() -> tuple[int, int]:
    values = [int(v) for v in read_text("/proc/stat").splitlines()[0].split()[1:9]]
    return sum(values), values[3] + values[4]


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
    gpu_sources = dict.fromkeys(item["source"] for item in gpus)
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
