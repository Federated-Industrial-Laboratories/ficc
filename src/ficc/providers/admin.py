# SPDX-License-Identifier: Apache-2.0
"""Carry fixed admin batches over enrolled SSH and validate every response."""

import asyncio

from ficc_node import admin_spec as spec

from ..errors import Failure
from ..ssh import transport_failure
from .libvirt import entry

COMMAND = entry("admin_rpc")


def response_error(value):
    spec.fields(value, {"code", "message"})
    spec.text(value["code"], 96)
    spec.text(value["message"], 256)


def description(value):
    spec.fields(value, set(spec.EXPECTED) | {"detail", "metrics"})
    spec.expected({key: value[key] for key in spec.EXPECTED})
    spec.text(value["detail"], 128, empty=True)
    if value["metrics"] is not None:
        spec.fields(value["metrics"], {"uptime_seconds", "memory_total", "memory_available"})
        for item in value["metrics"].values():
            spec.integer(item, 0, 2**53 - 1)
    return value


def validate(value, request):
    action, params = request["action"], request["parameters"]
    if action == "forget":
        if value != {"removed": True} or type(value["removed"]) is not bool:
            raise ValueError("The admin receipt removal was not acknowledged.")
        return value
    if action == "probe":
        spec.fields(value, {"binding", "provider", "version", "account_uid", "system_id"})
        spec.fingerprint(value["binding"])
        spec.fingerprint(value["system_id"])
        spec.text(value["version"], 128)
        spec.integer(value["account_uid"], 0, 2**32 - 1)
        if value["provider"] != request["provider"]:
            raise ValueError("The admin provider identity changed.")
        return value
    if action == "list":
        spec.fields(value, {"results", "next_offset", "truncated"})
        maximum, expected = params["limit"], None
        if type(value["truncated"]) is not bool or value["truncated"] != (value["next_offset"] is not None):
            raise ValueError("Invalid admin pagination.")
        if value["next_offset"] is not None:
            spec.integer(value["next_offset"], params["offset"] + 1, 4352)
    elif action in {"status", "logs"}:
        spec.fields(value, {"results"})
        expected = params["resources"]
        maximum = len(expected)
    else:
        spec.fields(value, {"results", "digest"})
        frozen = {key: request[key] for key in ("profile", "provider", "manager", "binding")}
        frozen["intent"] = params["intent"]
        if value["digest"] != spec.digest(frozen):
            raise ValueError("The admin receipt intent does not match.")
        expected = [item["resource"] for item in params["intent"]["expected"]]
        maximum = len(expected)
    rows = value["results"]
    if not isinstance(rows, list) or len(rows) > maximum:
        raise ValueError("Invalid admin result count.")
    pointers = []
    for row in rows:
        spec.pointer(row.get("resource"))
        pointers.append(row["resource"])
        if action in {"apply", "receipt"}:
            spec.fields(row, {"resource", "state"}, {"error"})
            if row["state"] not in {"accepted", "refused", "unknown"}:
                raise ValueError("Invalid admin receipt state.")
        else:
            spec.fields(row, {"resource"}, {"data", "error"})
            if ("data" in row) == ("error" in row):
                raise ValueError("Invalid admin result outcome.")
            if "data" in row:
                if action == "logs":
                    spec.fields(row["data"], {"text", "truncated"})
                    data = row["data"]
                    if not isinstance(data["text"], str) or len(data["text"].encode()) > params["byte_limit"] * 3 or type(data["truncated"]) is not bool:
                        raise ValueError("Administration logs exceed their limit.")
                else:
                    data = description(row["data"])
                    keys = ("id", "kind", "name")
                    if any(data["resource"][key] != row["resource"][key] for key in keys):
                        raise ValueError("The admin result identity changed.")
        if "error" in row:
            response_error(row["error"])
    ids = [spec.resource(request["profile"], pointer) for pointer in pointers]
    if len(set(ids)) != len(ids) or expected is not None and pointers != expected:
        raise ValueError("Administration results changed order or identity.")
    if action == "list" and value["next_offset"] is not None and value["next_offset"] != params["offset"] + len(rows):
        raise ValueError("The admin page did not advance.")
    return value


class Transport:
    def __init__(self, service):
        self.service = service
        self.semaphore = asyncio.Semaphore(4)
        self.pending = 0

    async def request(self, node, profile, action, parameters, check):
        payload = spec.request({"version": 1, "action": action, "profile": profile["id"],
            **{key: profile[key] for key in ("provider", "manager", "binding")}, "parameters": parameters})
        if self.pending >= 64:
            raise Failure("admin_busy", "The admin request queue is full.", 429)
        self.pending += 1
        try:
            async with self.semaphore:
                check()
                code, output, stderr = await self.service.ssh.command(node, COMMAND, spec.encode(payload), check=check,
                                                                     timeout=22 if action == "apply" else 7)
                check()
                if code:
                    if code == 42 or b"No module named" in stderr:
                        raise Failure("admin_helper_upgrade", "Install the current FICC node helper on this system.", 409)
                    raise transport_failure(stderr)
                try:
                    value = spec.decode(output)
                    spec.fields(value, {"version"}, {"data", "error"})
                    if type(value["version"]) is not int or value["version"] != 1 or ("data" in value) == ("error" in value):
                        raise ValueError("Invalid admin response envelope.")
                    if "error" in value:
                        response_error(value["error"])
                        raise Failure(value["error"]["code"], value["error"]["message"], 409)
                    return validate(value["data"], payload)
                except (ValueError, KeyError, TypeError, RecursionError) as exc:
                    raise Failure("admin_invalid_response", "The admin helper response is invalid.", 502) from exc
        finally:
            self.pending -= 1
