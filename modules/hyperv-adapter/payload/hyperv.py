# SPDX-License-Identifier: Apache-2.0
"""Interpret fixed Hyper-V command results without credentials or network access."""

import hashlib
import json
import re
import uuid

HASH = re.compile(r"[0-9a-f]{64}\Z")
STATES = {2: "running", 3: "off", 4: "shutting-down", 6: "off", 9: "paused",
          32768: "paused", 32769: "suspended", 32773: "suspended", 32774: "shutting-down"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError("The endpoint result fields differ.")


def guid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("The VM identifier is not canonical.")
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("The endpoint number exceeds its limit.")
    return value


def row(value):
    exact(value, {"key", "birth", "revision", "name", "state", "memory_bytes", "vcpus", "console"})
    key = guid(value["key"])
    if any(not isinstance(value[name], str) or HASH.fullmatch(value[name]) is None
           for name in ("birth", "revision")):
        raise ValueError("The VM birth or revision is absent.")
    if (not isinstance(value["name"], str) or not 1 <= len(value["name"]) <= 256
            or any(ord(char) < 32 for char in value["name"]) or type(value["console"]) is not bool):
        raise ValueError("The VM display fields are invalid.")
    identity = {"key": key, "birth": value["birth"]}
    resource = {**identity, "id": digest(identity)[:32], "revision": value["revision"],
                "state": STATES.get(integer(value["state"], 0, 65535), "unknown")}
    return {"resource": resource, "name": value["name"],
            "memory_kib": integer(value["memory_bytes"], 0, 2**53 - 1) // 1024,
            "vcpus": integer(value["vcpus"], 1, 65536), "console": value["console"]}


def call(transport, binding, command, value=None):
    params = {} if value is None else {"Request": json.dumps(value, separators=(",", ":"), ensure_ascii=True)}
    result = transport(binding["id"], [{"command": command, "parameters": params}])
    if not isinstance(result, list) or len(result) != 1:
        raise ValueError("The endpoint response count differs.")
    return result[0]


def snapshot(transport, binding, inventory=False):
    params = binding["parameters"]
    request = {"ids": [guid(item["key"]) for item in binding["resources"]],
               "offset": integer(params.get("offset", 0), 0, 4096) if inventory else 0,
               "limit": integer(params.get("limit", 64), 1, 256) if inventory else 64}
    result = call(transport, binding, "Get-FICCHyperVSnapshot", request)
    exact(result, {"rows", "next_offset"})
    if not isinstance(result["rows"], list) or len(result["rows"]) > request["limit"]:
        raise ValueError("The endpoint inventory exceeds its limit.")
    rows = [row(item) for item in result["rows"]]
    ids = [item["resource"]["key"] for item in rows]
    if len(ids) != len(set(ids)) or (request["ids"] and set(ids) - set(request["ids"])):
        raise ValueError("The endpoint returned unrelated VM identities.")
    if result["next_offset"] is not None:
        integer(result["next_offset"], request["offset"] + 1, 4096)
    return rows, result["next_offset"]


def error(code="changed", message="The VM identity or configuration changed."):
    return {"code": code, "message": message}


def current(rows, resource, revision=False):
    item = next((item for item in rows if item["resource"]["id"] == resource["id"]), None)
    names = ("id", "key", "birth", "revision", "state") if revision else ("id", "key", "birth")
    return item if item and all(item["resource"][name] == resource[name] for name in names) else None


def receipt(state, token=None, task="none"):
    return {"state": state, "token": token or {}, "completed": state in {"observed", "failed", "refused"},
            "result": "success" if state == "observed" else "failure" if state in {"failed", "refused"} else "unknown",
            "task_state": task}


def intent(binding, resource, action):
    targets = binding["intent"]["targets"]
    selected = [item for item in targets if item["id"] == resource["id"]]
    expected = {"resource": resource, "action": action, "method": "RequestStateChange" if action == "start" else "InitiateShutdown"}
    if len(selected) != 1 or selected[0]["intent"] != expected:
        raise ValueError("The frozen provider intent differs.")
    return expected


def apply(transport, binding, action):
    selected = binding["resources"]
    targets = [intent(binding, resource, action) for resource in selected]
    result = call(transport, binding, "Invoke-FICCHyperVPower", {"targets": targets})
    exact(result, {"results"})
    if not isinstance(result["results"], list) or len(result["results"]) != len(selected):
        raise ValueError("The method acknowledgement count differs.")
    output = []
    for value, resource in zip(result["results"], selected, strict=True):
        exact(value, {"key", "birth", "dispatched", "return_value", "job"})
        if value["key"] != resource["key"] or value["birth"] != resource["birth"] or type(value["dispatched"]) is not bool:
            raise ValueError("The method acknowledgement identity differs.")
        if not value["dispatched"]:
            proof = receipt("refused")
        else:
            code = integer(value["return_value"], 0, 2**32 - 1)
            job = value["job"]
            if job is not None:
                guid(job)
            token = {"key": resource["key"], "birth": resource["birth"], "action": action,
                     "method": targets[len(output)]["method"], "return_value": code, "job": job}
            if code == 0:
                proof = receipt("accepted", token)
            elif code == 4096:
                proof = receipt("accepted" if job is not None and action == "start" else "unknown",
                                token, "active" if job is not None and action == "start" else "unknown")
            else:
                proof = receipt("failed", token, "finished")
        output.append({"id": resource["id"], "receipt": proof})
    return {"results": output}


def observe(transport, binding, action):
    rows, _ = snapshot(transport, binding)
    prior = binding["receipt"]["targets"]
    if [item["id"] for item in prior] != [item["id"] for item in binding["resources"]]:
        raise ValueError("The prior receipt order differs.")
    jobs = []
    for item in prior:
        proof = item["receipt"]
        if proof and not proof["completed"] and proof["token"].get("job"):
            jobs.append(guid(proof["token"]["job"]))
    tasks = {}
    if jobs:
        response = call(transport, binding, "Get-FICCHyperVTasks", {"ids": jobs})
        exact(response, {"results"})
        if not isinstance(response["results"], list) or len(response["results"]) != len(jobs):
            raise ValueError("The job response count differs.")
        for key, item in zip(jobs, response["results"], strict=True):
            exact(item, {"id", "state", "error"})
            if item["id"] != key:
                raise ValueError("The job identity differs.")
            tasks[key] = (integer(item["state"], 0, 65535), integer(item["error"], 0, 2**32 - 1))
    output = []
    for resource, previous in zip(binding["resources"], prior, strict=True):
        intent(binding, resource, action)
        now, proof = current(rows, resource), previous["receipt"]
        if not proof or not proof["token"]:
            proof = receipt("unknown")
        else:
            token = proof["token"]
            expected_method = "RequestStateChange" if action == "start" else "InitiateShutdown"
            if any(token.get(key) != expected for key, expected in (("key", resource["key"]),
                    ("birth", resource["birth"]), ("action", action), ("method", expected_method))):
                raise ValueError("The saved acknowledgement belongs to another operation.")
            job = token.get("job")
            acknowledged = token.get("return_value") == 0
            if proof["completed"]:
                output.append({"id": resource["id"], "receipt": proof,
                               **({"observed_state": now["resource"]["state"]} if now else {})})
                continue
            if job:
                state, code = tasks[job]
                if state == 7:
                    proof = receipt("failed" if code else "accepted", token, "finished" if code else "none")
                    acknowledged = code == 0
                elif state in {8, 9, 10}:
                    proof = receipt("failed", token, "finished")
                else:
                    proof = receipt("accepted", token, "active" if state else "unknown")
            if acknowledged and now and now["resource"]["state"] == {"start": "running", "shutdown": "off"}[action]:
                proof = receipt("observed", token, "finished" if job else "none")
        item = {"id": resource["id"], "receipt": proof}
        if now:
            item["observed_state"] = now["resource"]["state"]
        output.append(item)
    return {"results": output}


def phase(request, binding, transport):
    name, action = request["phase"], request["action"]
    if name == "probe":
        result = call(transport, binding, "Get-FICCHyperVVersion")
        exact(result, {"version", "backend"})
        if result["backend"] != 1 or not isinstance(result["version"], str) or not 1 <= len(result["version"]) <= 160:
            raise ValueError("The endpoint backend version differs.")
        return {"provider": {"name": "Microsoft Hyper-V", "version": result["version"], "fingerprint": digest(result)}}
    if name == "apply":
        return apply(transport, binding, action)
    if name == "observe":
        return observe(transport, binding, action)
    rows, offset = snapshot(transport, binding, name == "inventory")
    if name == "inventory":
        return {"resources": rows, "next_offset": offset, "truncated": offset is not None}
    if name == "console":
        resource = binding["resources"][0]
        if len(binding["resources"]) != 1 or not current(rows, resource, True):
            raise ValueError("The selected console changed.")
        return {"resource": resource, "kind": "vmconnect", "binding_id": binding["endpoint_id"],
                "parameters": {"vm_id": guid(resource["key"])}}
    output = []
    for resource in binding["resources"]:
        now = current(rows, resource, name == "prepare")
        item = {"id": resource["id"]}
        if not now:
            item["error"] = error()
        elif name == "status":
            item["data"] = now
        elif resource["state"] != {"start": "off", "shutdown": "running"}[action]:
            item["error"] = error("state", "The VM state does not permit this action.")
        else:
            item.update(intent={"resource": resource, "action": action,
                        "method": "RequestStateChange" if action == "start" else "InitiateShutdown"},
                        desired_state="running" if action == "start" else "off")
        output.append(item)
    return {"results": output}


def handle(request, transport):
    output = []
    for binding in request["bindings"]:
        try:
            if binding["consistency"] != "checked-before-dispatch":
                raise ValueError("The provider consistency class differs.")
            output.append({"profile_id": binding["id"], "data": phase(request, binding, transport)})
        except (ValueError, KeyError, TypeError):
            output.append({"profile_id": binding["id"], "error": error("provider", "The Hyper-V command or result was refused.")})
    return output
