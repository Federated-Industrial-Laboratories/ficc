# SPDX-License-Identifier: Apache-2.0
"""Observe Apple Silicon driver statistics without root or power-management changes."""

import plistlib
import subprocess
from xml.parsers.expat import ExpatError

from .gpu import number
from .metric_command import read_command


def apple_metrics() -> tuple[list[dict], str]:
    try:
        raw = read_command(["/usr/sbin/ioreg", "-a", "-r", "-d", "1", "-c", "AGXAccelerator"],
                           maximum=1048576)
        entries = plistlib.loads(raw)
        if not isinstance(entries, list) or len(entries) > 64:
            raise ValueError("Invalid GPU registry response.")
        metrics = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Invalid GPU registry entry.")
            identity = entry.get("IORegistryEntryID")
            if type(identity) is not int or not 0 <= identity <= 2**64 - 1:
                raise ValueError("GPU registry identity is unavailable.")
            name = entry.get("model", "Apple GPU")
            if isinstance(name, bytes):
                name = name.rstrip(b"\0").decode("utf-8", errors="replace")
            if not isinstance(name, str) or not name.strip() or not name.isprintable():
                name = "Apple GPU"
            stats = entry.get("PerformanceStatistics", {})
            if not isinstance(stats, dict):
                stats = {}
            metrics.append({"uuid": f"APPLE-REGISTRY-{identity:x}", "name": name[:256],
                            "source": "apple-ioreg", "memory_kind": "unified",
                            "reservation_supported": False,
                            # Unified RAM and allocated bytes are not a dedicated VRAM capacity.
                            "memory_total_bytes": None,
                            "memory_used_bytes": number(stats.get("In use system memory")),
                            "utilization_percent": number(stats.get("Device Utilization %"), maximum=100),
                            "temperature_c": None})
        if not metrics:
            return [], "unsupported"
        measured = any(gpu["utilization_percent"] is not None or gpu["memory_used_bytes"] is not None
                       for gpu in metrics)
        return metrics, "available" if measured else "unavailable"
    except (OSError, ValueError, UnicodeError, plistlib.InvalidFileException,
            subprocess.SubprocessError, OverflowError, ExpatError):
        return [], "unavailable"
