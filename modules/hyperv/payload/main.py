# SPDX-License-Identifier: Apache-2.0
"""Present VM inventory and request host-owned previews or viewer references."""

import runpy
from pathlib import Path


def handle(request, broker):
    action = request["action"]
    params = request["parameters"]
    if action == "profiles":
        values = broker("vm.adapter.profiles", request["targets"], {"adapter_id": "org.ficc.hyperv-adapter"})
        choices = [item for result in values if "data" in result for item in result["data"]["profiles"]]
        if len(choices) > 64:
            raise ValueError("The provider profile count exceeds its limit.")
        return [{"target": target, "data": {"profiles": choices if index == 0 else []}}
                for index, target in enumerate(request["targets"])]
    if action == "load":
        values = broker("vm.adapter.list", request["targets"],
                        {"profile_id": params["profile_id"], "offset": params.get("offset", 0), "limit": min(64, 128 // len(request["targets"]))})
        rows, notices = [], []
        for result in values:
            if "error" in result:
                notices.append(result["target"] + ": " + result["error"]["message"])
                continue
            data = result["data"]
            if data["truncated"]:
                notices.append(result["target"] + ": More VMs are available from offset " + str(data["next_offset"]) + ".")
            for item in data["results"]:
                vm = item.get("data", {})
                rows.append({"id": item["vm_id"], "values": {"name": vm.get("name", "Unavailable"),
                    "system": result["target"], "state": vm.get("state", "unavailable"),
                    "vcpus": vm.get("vcpus", ""), "memory": vm.get("memory_kib", ""),
                    "error": item.get("error", {}).get("message", "")}})
        return [{"target": target, "data": {"rows": rows if index == 0 else [],
                 "notice": " ".join(notices)[:8192] if index == 0 else ""}}
                for index, target in enumerate(request["targets"])]
    if action in {"preview-start", "preview-shutdown"}:
        return broker("vm.adapter.preview", request["targets"],
                      {"profile_id": params["profile_id"], "action": action.removeprefix("preview-"), "vm_ids": params["vm_ids"]})
    if action == "open-console":
        return broker("vm.adapter.console", request["targets"], {"profile_id": params["profile_id"], "vm_ids": params["vm_ids"]})
    raise ValueError("Unsupported VM action.")


sdk = runpy.run_path(str(Path(__file__).with_name("ficc_module.py")))
raise SystemExit(sdk["serve_broker"](handle))
