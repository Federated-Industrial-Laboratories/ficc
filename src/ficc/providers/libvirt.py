# SPDX-License-Identifier: Apache-2.0
"""Carry validated libvirt batches over the enrolled, pinned SSH identity."""

import asyncio
import shlex

from ficc_node import vm_spec as spec

from ..errors import Failure
from ..ssh import transport_failure


def entry(module):
    code = f"import runpy,sys;sys.path.insert(0,sys.argv[1]);runpy.run_module('ficc_node.{module}',run_name='__main__')"
    return ('test -f "$HOME/.local/lib/ficc/node.pyz" || exit 42; exec python3 -c '
            + shlex.quote(code) + ' "$HOME/.local/lib/ficc/node.pyz"')


COMMAND = entry("vm_rpc")
CONSOLE_COMMAND = entry("vm_console")


def response_error(value):
    spec.fields(value, {"code", "message"})
    spec.text(value["code"], 96)
    spec.text(value["message"], 256)


def description(value):
    spec.fields(value, {"uuid", "name", "state", "vcpus", "memory_kib", "max_memory_kib", "definition"})
    spec.identity(value["uuid"])
    spec.text(value["name"])
    spec.fingerprint(value["definition"])
    if value["state"] not in spec.STATES.values():
        raise ValueError("Invalid VM state.")
    for key in ("memory_kib", "max_memory_kib"):
        spec.integer(value[key], 0, 9007199254740991)
    spec.integer(value["vcpus"], 0, 65536)


def validate(value, request):
    action, params = request["action"], request["parameters"]
    if action == "forget":
        spec.fields(value, {"removed"})
        if value["removed"] is not True:
            raise ValueError("The VM receipt removal was not acknowledged.")
        return value
    if action == "console":
        spec.fields(value, {"uuid", "protocol", "graphics_index", "audio", "authentication"})
        if (value["uuid"] != params["uuids"][0] or value["protocol"] != "vnc"
                or value["audio"] is not False or value["authentication"] != "rfb"):
            raise ValueError("Invalid console identity.")
        spec.integer(value["graphics_index"], 0, 63)
        return value
    if action == "list":
        spec.fields(value, {"results", "total", "next_offset", "truncated", "inventory_digest"})
        spec.integer(value["total"], 0, 4096)
        spec.fingerprint(value["inventory_digest"])
        if type(value["truncated"]) is not bool or value["truncated"] != (value["next_offset"] is not None):
            raise ValueError("Invalid VM pagination.")
        if value["next_offset"] is not None:
            spec.integer(value["next_offset"], params["offset"] + 1, value["total"] - 1)
        expected = None
        maximum = params["limit"]
    elif action == "status":
        spec.fields(value, {"results"})
        expected, maximum = params["uuids"], len(params["uuids"])
    else:
        spec.fields(value, {"results", "digest"})
        expected = [item["uuid"] for item in params["intent"]["expected"]]
        maximum = len(expected)
        identity = {key: request[key] for key in ("connection", "profile")}
        identity["intent"] = params["intent"]
        if value["digest"] != spec.digest(identity):
            raise ValueError("Invalid VM receipt identity.")
    rows = value["results"]
    if not isinstance(rows, list) or len(rows) > maximum:
        raise ValueError("Invalid VM result count.")
    ids = []
    for row in rows:
        if action in {"apply", "receipt"}:
            spec.fields(row, {"uuid", "state"}, {"error"})
            if row["state"] not in {"accepted", "refused", "unknown"}:
                raise ValueError("Invalid VM receipt state.")
            if "error" in row:
                response_error(row["error"])
        else:
            spec.fields(row, {"uuid"}, {"data", "error"})
            if ("data" in row) == ("error" in row):
                raise ValueError("Invalid VM result outcome.")
            if "data" in row:
                description(row["data"])
                if row["data"]["uuid"] != row["uuid"]:
                    raise ValueError("Invalid VM result identity.")
            else:
                response_error(row["error"])
        ids.append(spec.identity(row["uuid"]))
    if len(ids) != len(set(ids)) or expected is not None and ids != expected:
        raise ValueError("Invalid VM result order or identity.")
    if action == "list":
        end = params["offset"] + len(rows)
        if (value["next_offset"] is not None and value["next_offset"] != end
                or len(rows) != min(params["limit"], max(0, value["total"] - params["offset"]))):
            raise ValueError("Invalid VM page length.")
    return value


class Transport:
    def __init__(self, service):
        self.service = service
        self.semaphore = asyncio.Semaphore(4)
        self.pending = 0

    async def request(self, node, profile, action, parameters, check):
        payload = spec.request({"version": 1, "action": action, "profile": profile["id"],
                                "connection": profile["connection"], "parameters": parameters})
        if self.pending >= 64:
            raise Failure("vm_busy", "The VM request queue is full.", 429)
        self.pending += 1
        try:
            async with self.semaphore:
                check()
                code, output, stderr = await self.service.ssh.command(
                    node, COMMAND, spec.encode(payload), check=check, timeout=8)
                check()
                if code:
                    if code == 42 or b"No module named" in stderr:
                        raise Failure("vm_helper_upgrade", "Install the current FICC node helper on this system.", 409)
                    raise transport_failure(stderr)
                try:
                    value = spec.decode(output)
                    spec.fields(value, {"version"}, {"data", "error"})
                    if type(value["version"]) is not int or value["version"] != 1 or ("data" in value) == ("error" in value):
                        raise ValueError("Invalid VM response envelope.")
                    if "error" in value:
                        response_error(value["error"])
                        raise Failure(value["error"]["code"], value["error"]["message"], 409)
                    return validate(value["data"], payload)
                except (ValueError, KeyError, TypeError, RecursionError) as exc:
                    raise Failure("vm_invalid_response", "The VM helper response is invalid.", 502) from exc
        finally:
            self.pending -= 1
