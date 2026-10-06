# SPDX-License-Identifier: Apache-2.0
"""Read native macOS resource counters without a third-party daemon."""

import ctypes
import os
import re
import subprocess
import sys
import time
import uuid

from . import VERSION


def command(*argv: str) -> str:
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=3, check=True)
    if len(result.stdout) > 262144:
        raise ValueError("The macOS resource response exceeds capacity.")
    return result.stdout


def boot_id() -> str:
    return str(uuid.UUID(command("/usr/sbin/sysctl", "-n", "kern.bootsessionuuid").strip()))


def cpu_ticks() -> tuple[int, int]:
    library = ctypes.CDLL(None)
    library.mach_host_self.restype = ctypes.c_uint
    library.host_statistics.argtypes = [ctypes.c_uint, ctypes.c_int,
                                       ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_uint)]
    ticks = (ctypes.c_int * 4)()
    count = ctypes.c_uint(4)
    # HOST_CPU_LOAD_INFO: user, system, idle, nice, in clock ticks.
    if library.host_statistics(library.mach_host_self(), 3, ticks, ctypes.byref(count)) or count.value != 4:
        raise ValueError("The macOS CPU counters are unavailable.")
    values = [value & 0xffffffff for value in ticks]
    return sum(values), values[2]


def memory_available(output: str) -> int:
    page_size = re.search(r"page size of (\d+) bytes", output)
    if page_size is None:
        raise ValueError("The macOS memory page size is unavailable.")
    pages = dict(re.findall(r"^([^:\n]+):\s+(\d+)\.", output, re.MULTILINE))
    return int(page_size[1]) * sum(int(pages[name]) for name in
                                   ("Pages free", "Pages inactive", "Pages speculative"))


def network_counters(output: str) -> list[dict]:
    counters = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[2].startswith("<Link#"):
            # Link rows may omit a hardware address. The seven trailing
            # counters have the same layout in either form.
            values = fields[-7:]
            counters.append({"name": fields[0].rstrip("*"),
                             "rx_bytes": int(values[2]), "tx_bytes": int(values[5])})
    return counters[:64]


def collect() -> dict:
    first_total, first_idle = cpu_ticks()
    time.sleep(0.1)
    total, idle = cpu_ticks()
    delta = total - first_total
    percent = max(0.0, min(100.0, 100 * (1 - (idle - first_idle) / delta))) if delta > 0 else None
    memory = int(command("/usr/sbin/sysctl", "-n", "hw.memsize"))
    available = memory_available(command("/usr/bin/vm_stat"))
    boot = command("/usr/sbin/sysctl", "-n", "kern.boottime")
    match = re.search(r"sec\s*=\s*(\d+)", boot)
    if match is None:
        raise ValueError("The macOS boot time is unavailable.")
    mount = "/System/Volumes/Data" if os.path.isdir("/System/Volumes/Data") else "/"
    disk = os.statvfs(mount)
    return {
        "version": "1", "boot_id": boot_id(),
        "observed_at": time.time(), "monotonic_seconds": time.monotonic(),
        "capabilities": {"resources": True, "gpu_metrics": False,
                         "jobs": False, "files": False, "terminals": False,
                         "source": "macos-mach-sysctl", "gpu_source": "unsupported"},
        "resources": {
            "cpu_percent": percent, "cpu_count": os.cpu_count() or 1,
            "load": list(os.getloadavg()), "memory_total_bytes": memory,
            "memory_available_bytes": min(memory, available),
            "uptime_seconds": max(0.0, time.time() - int(match[1])),
            "storage": [{"mount": mount, "total_bytes": disk.f_blocks * disk.f_frsize,
                         "available_bytes": disk.f_bavail * disk.f_frsize}],
            "network": network_counters(command("/usr/sbin/netstat", "-ibn")),
            "gpus": [], "gpu_status": "unsupported",
        },
        "helper_version": VERSION, "python_version": "python" + sys.version.split()[0],
    }
