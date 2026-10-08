# SPDX-License-Identifier: Apache-2.0
"""Combine independent GPU observations without inferring missing measurements."""

from __future__ import annotations

import csv
import io
import math
import platform
import shutil
import subprocess

from .metric_command import read_command


def number(value, multiplier: float = 1, minimum: float = 0,
           maximum: float = 2**63 - 1) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        result = float(value) * multiplier
        return result if math.isfinite(result) and minimum <= result <= maximum else None
    except (ValueError, TypeError, OverflowError):
        return None


def nvidia_metrics() -> tuple[list[dict], str]:
    executable = shutil.which("nvidia-smi")
    if executable is None:
        return [], "unsupported"
    command = [executable, "--query-gpu=uuid,name,memory.total,memory.used,utilization.gpu,temperature.gpu",
               "--format=csv,noheader,nounits"]
    try:
        rows = list(csv.reader(io.StringIO(read_command(command).decode("utf-8")), skipinitialspace=True))
        if len(rows) > 64:
            raise ValueError("Too many GPUs.")
        metrics = []
        for row in rows:
            if len(row) != 6:
                raise ValueError("GPU response is invalid.")
            uuid, name, total, used, utilization, temperature = [v.strip() for v in row]
            if any(not value or len(value) > 256 or not value.isprintable() for value in (uuid, name)):
                raise ValueError("GPU identity is invalid.")
            metrics.append({"uuid": uuid, "name": name, "source": "nvidia-smi",
                            "memory_kind": "vram", "reservation_supported": True,
                            "memory_total_bytes": number(total, 1048576),
                            "memory_used_bytes": number(used, 1048576),
                            "utilization_percent": number(utilization, maximum=100),
                            "temperature_c": number(temperature, minimum=-100, maximum=300)})
        return metrics, "available" if metrics else "unsupported"
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError):
        return [], "unavailable"


def gpu_metrics() -> tuple[list[dict], str]:
    system = platform.system()
    if system == "Darwin":
        from .gpu_apple import apple_metrics
        return apple_metrics()
    if system != "Linux":
        return [], "unsupported"
    from .gpu_amd import metrics as amd_metrics
    results = [nvidia_metrics(), amd_metrics()]
    metrics = [gpu for devices, _ in results for gpu in devices][:64]
    status = ("available" if any(status == "available" for _, status in results) else
              "unavailable" if any(status == "unavailable" for _, status in results) else "unsupported")
    return metrics, status
