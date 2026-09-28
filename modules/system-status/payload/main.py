# SPDX-License-Identifier: Apache-2.0
"""Show granted system measurements through the constrained host read primitive."""

import runpy
from pathlib import Path


def load(request, broker):
    values = broker("system.resources.read", request["targets"])
    rows = []
    for item in values:
        data = item.get("data", {})
        sample = data.get("resources") or {}
        total, available = sample.get("memory_total_bytes"), sample.get("memory_available_bytes")
        memory = round((total - available) / total * 100, 1) if total and available is not None else None
        rows.append({"id": item["target"], "values": {
            "name": data.get("name", item["target"]), "state": data.get("state", "unavailable"),
            "cpu": sample.get("cpu_percent"), "memory": memory,
            "uptime": sample.get("uptime_seconds"), "freshness": "Stale" if data.get("stale", True) else "Current",
            "error": item.get("error", {}).get("message", ""),
        }})
    return [{"target": target, "data": {"rows": rows if index == 0 else []}}
            for index, target in enumerate(request["targets"])]


sdk = runpy.run_path(str(Path(__file__).with_name("ficc_module.py")))
raise SystemExit(sdk["serve_broker"](load))
