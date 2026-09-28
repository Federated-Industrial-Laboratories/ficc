# SPDX-License-Identifier: Apache-2.0
"""Present bounded container data and request host-owned action previews."""

import runpy
from pathlib import Path


def handle(request, broker):
    action, params, targets = request["action"], request["parameters"], request["targets"]
    if action.startswith("preview-"):
        values = {"action": action.removeprefix("preview-"), "resource_ids": params["resource_ids"]}
        if action == "preview-scale":
            values["replicas"] = params["replicas"]
        return broker("container.preview", targets, values)
    if action == "logs":
        values = broker("container.logs", targets, {"resource_ids": params["resource_ids"], "tail": 100,
            "byte_limit": 16384, "container": params.get("container", "")})
        lines = []
        for result in values:
            if "error" in result:
                lines.append(result["error"]["message"])
                continue
            for profile in result["data"]["profiles"]:
                if "error" in profile:
                    lines.append(profile["error"]["message"])
                    continue
                for row in profile["data"]["results"]:
                    lines.append(result["target"] + " / " + row["resource"]["name"])
                    data = row.get("data", {})
                    lines.extend(data.get("text", row.get("error", {}).get("message", "")).splitlines())
                    if data.get("truncated"):
                        lines.append("The provider log reached its byte limit.")
        bounded, remaining = [], 16000
        for line in lines[:127]:
            text = line[:min(2048, remaining)]
            bounded.append(text)
            remaining -= len(text)
            if remaining <= 0:
                break
        if len(bounded) < len(lines) or any(len(line) > 2048 for line in lines):
            bounded.append("The log view reached its display limit.")
        return [{"target": target, "data": {"lines": bounded if index == 0 else []}} for index, target in enumerate(targets)]
    if action != "load":
        raise ValueError("Unsupported container action.")
    values = broker("container.list", targets, {"provider": params.get("provider", "all"), "kind": params.get("kind", "all"),
        "offset": params.get("offset", 0), "limit": 128})
    rows, notices = [], []
    for result in values:
        if "error" in result:
            notices.append(result["target"] + ": " + result["error"]["message"])
            continue
        for profile in result["data"]["profiles"]:
            if "error" in profile:
                notices.append(result["target"] + ": " + profile["error"]["message"])
                continue
            data = profile["data"]
            if data["truncated"]:
                notices.append(result["target"] + " / " + profile["provider"] + ": More workloads start at offset " + str(data["next_offset"]) + ".")
            for row in data["results"]:
                item = row.get("data", {})
                pointer = item.get("resource", row["resource"])
                rows.append({"id": row["resource_id"], "values": {"name": pointer["name"], "kind": pointer["kind"],
                    "system": result["target"], "provider": profile["provider"], "namespace": pointer["namespace"],
                    "state": item.get("state", "unavailable"), "replicas": item.get("replicas"),
                    "error": row.get("error", {}).get("message", "")}})
    return [{"target": target, "data": {"rows": rows if index == 0 else [], "notice": " ".join(notices)[:8192] if index == 0 else ""}}
            for index, target in enumerate(targets)]


if __name__ == "__main__":
    sdk = runpy.run_path(str(Path(__file__).with_name("ficc_module.py")))
    raise SystemExit(sdk["serve_broker"](handle))
