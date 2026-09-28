# SPDX-License-Identifier: Apache-2.0
"""Carry fixed container batches over enrolled SSH and validate every response."""

import asyncio

from ficc_node import container_spec as spec

from ..errors import Failure
from ..ssh import transport_failure
from .libvirt import entry

COMMAND = entry("container_rpc")


def response_error(value):
    spec.fields(value, {"code", "message"})
    spec.text(value["code"], 96)
    spec.text(value["message"], 256)


def description(value):
    spec.fields(value, {"resource", "state", "revision", "definition", "image", "replicas", "ready", "containers"})
    spec.expected({key: value[key] for key in ("resource", "state", "revision", "definition", "replicas")})
    spec.text(value["image"])
    if value["ready"] is not None:
        spec.integer(value["ready"], 0, 1000000)
    names = value["containers"]
    if not isinstance(names, list) or len(names) > 64:
        raise ValueError("Invalid pod container names.")
    for name in names:
        spec.name(name, 63)
    if len(set(names)) != len(names):
        raise ValueError("Duplicate pod container name.")
    return value


def validate(value, request):
    action, params = request["action"], request["parameters"]
    if action == "forget":
        if value != {"removed": True} or type(value["removed"]) is not bool:
            raise ValueError("The container receipt removal was not acknowledged.")
        return value
    if action == "probe":
        spec.fields(value, {"binding", "provider", "version", "account_uid"})
        spec.fingerprint(value["binding"])
        spec.text(value["version"], 128)
        spec.integer(value["account_uid"], 0, 2**32 - 1)
        if value["provider"] != request["provider"]:
            raise ValueError("The container provider identity changed.")
        return value
    if action == "list":
        spec.fields(value, {"results", "next_offset", "truncated"})
        maximum, expected = params["limit"], None
        if type(value["truncated"]) is not bool or value["truncated"] != (value["next_offset"] is not None):
            raise ValueError("Invalid container pagination.")
        if value["next_offset"] is not None:
            spec.integer(value["next_offset"], params["offset"] + 1, 4352)
    elif action in {"status", "logs"}:
        spec.fields(value, {"results"})
        expected = params["resources"]
        maximum = len(expected)
    else:
        spec.fields(value, {"results", "digest"})
        frozen = {key: request[key] for key in ("profile", "provider", "connection", "context", "namespace", "binding")}
        frozen["intent"] = params["intent"]
        if value["digest"] != spec.digest(frozen):
            raise ValueError("The container receipt intent does not match.")
        expected = [item["resource"] for item in params["intent"]["expected"]]
        maximum = len(expected)
    rows = value["results"]
    if not isinstance(rows, list) or len(rows) > maximum:
        raise ValueError("Invalid container result count.")
    pointers = []
    for row in rows:
        spec.pointer(row.get("resource"))
        pointers.append(row["resource"])
        if action in {"apply", "receipt"}:
            spec.fields(row, {"resource", "state"}, {"error"})
            if row["state"] not in {"accepted", "refused", "unknown"}:
                raise ValueError("Invalid container receipt state.")
        else:
            spec.fields(row, {"resource"}, {"data", "error"})
            if ("data" in row) == ("error" in row):
                raise ValueError("Invalid container result outcome.")
            if "data" in row:
                if action == "logs":
                    spec.fields(row["data"], {"text", "truncated"})
                    data = row["data"]
                    if not isinstance(data["text"], str) or len(data["text"].encode()) > params["byte_limit"] * 3 or type(data["truncated"]) is not bool:
                        raise ValueError("Container logs exceed their limit.")
                else:
                    data = description(row["data"])
                    keys = ("id", "kind", "namespace") if row["resource"]["kind"] == "container" else ("id", "kind", "namespace", "name")
                    if any(data["resource"][key] != row["resource"][key] for key in keys):
                        raise ValueError("The container result identity changed.")
        if "error" in row:
            response_error(row["error"])
    ids = [spec.resource(request["profile"], pointer) for pointer in pointers]
    if len(set(ids)) != len(ids) or expected is not None and pointers != expected:
        raise ValueError("Container results changed order or identity.")
    if action == "list" and value["next_offset"] is not None and value["next_offset"] != params["offset"] + len(rows):
        raise ValueError("The container page did not advance.")
    return value


class Transport:
    def __init__(self, service):
        self.service = service
        self.semaphore = asyncio.Semaphore(4)
        self.pending = 0

    async def request(self, node, profile, action, parameters, check):
        payload = spec.request({"version": 1, "action": action, "profile": profile["id"],
            **{key: profile[key] for key in ("provider", "connection", "context", "namespace", "binding")}, "parameters": parameters})
        if self.pending >= 64:
            raise Failure("container_busy", "The container request queue is full.", 429)
        self.pending += 1
        try:
            async with self.semaphore:
                check()
                code, output, stderr = await self.service.ssh.command(node, COMMAND, spec.encode(payload), check=check,
                                                                     timeout=47 if action == "apply" else 22)
                check()
                if code:
                    if code == 42 or b"No module named" in stderr:
                        raise Failure("container_helper_upgrade", "Install the current FICC node helper on this system.", 409)
                    raise transport_failure(stderr)
                try:
                    value = spec.decode(output)
                    spec.fields(value, {"version"}, {"data", "error"})
                    if type(value["version"]) is not int or value["version"] != 1 or ("data" in value) == ("error" in value):
                        raise ValueError("Invalid container response envelope.")
                    if "error" in value:
                        response_error(value["error"])
                        raise Failure(value["error"]["code"], value["error"]["message"], 409)
                    return validate(value["data"], payload)
                except (ValueError, KeyError, TypeError, RecursionError) as exc:
                    raise Failure("container_invalid_response", "The container helper response is invalid.", 502) from exc
        finally:
            self.pending -= 1
