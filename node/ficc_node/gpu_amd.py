# SPDX-License-Identifier: Apache-2.0
"""Read optional AMDGPU sysfs counters without changing device settings."""

import re
from pathlib import Path

DRM_ROOT = Path("/sys/class/drm")
CARD = re.compile(r"card[0-9]+\Z")
PCI = re.compile(r"[0-9a-f]{4}:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]\Z")
HWMON = re.compile(r"hwmon[0-9]+\Z")


def read_value(path: Path, maximum: int = 64) -> str | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            return None
        return raw.decode("utf-8").strip()
    except (OSError, UnicodeError):
        return None


def number(path: Path, minimum: int, maximum: int) -> int | None:
    raw = read_value(path)
    if raw is None or not re.fullmatch(r"-?[0-9]+", raw):
        return None
    value = int(raw)
    return value if minimum <= value <= maximum else None


def temperature(device: Path) -> float | None:
    try:
        monitors = sorted((item for item in (device / "hwmon").iterdir()
                           if HWMON.fullmatch(item.name)), key=lambda item: int(item.name[5:]))
    except OSError:
        return None
    for monitor in monitors[:64]:
        if read_value(monitor / "name") == "amdgpu":
            value = number(monitor / "temp1_input", -100000, 300000)
            if value is not None:
                return value / 1000
    return None


def metrics() -> tuple[list[dict], str]:
    try:
        cards = sorted((item for item in DRM_ROOT.iterdir() if CARD.fullmatch(item.name)),
                       key=lambda item: int(item.name[4:]))
    except FileNotFoundError:
        return [], "unsupported"
    except OSError:
        return [], "unavailable"
    result = []
    seen = set()
    unavailable = False
    for card in cards:
        try:
            device = (card / "device").resolve(strict=True)
            if (device / "driver").resolve(strict=True).name != "amdgpu":
                continue
        except FileNotFoundError:
            continue
        except (OSError, RuntimeError):
            unavailable = True
            continue
        identity = device.name.lower()
        if not PCI.fullmatch(identity) or identity in seen:
            continue
        seen.add(identity)
        name = read_value(device / "product_name", 256)
        if not name or not name.isprintable():
            name = "AMD GPU (amdgpu)"
        total = number(device / "mem_info_vram_total", 0, 2**63 - 1)
        result.append({
            "uuid": "AMD-PCI-" + identity, "name": name,
            "memory_total_bytes": total,
            "memory_used_bytes": number(device / "mem_info_vram_used", 0, total if total is not None else 2**63 - 1),
            "utilization_percent": number(device / "gpu_busy_percent", 0, 100),
            "temperature_c": temperature(device),
        })
        if len(result) == 64:
            break
    return result, "available" if result else "unavailable" if unavailable else "unsupported"
