# SPDX-License-Identifier: Apache-2.0
"""Carry fixed local Proxmox requests through the enrolled SSH identity."""

from ficc_node import proxmox_spec as spec

from ..errors import Failure
from ..ssh import transport_failure
from . import libvirt as common

COMMAND = common.entry("proxmox_rpc")
CONSOLE_COMMAND = common.entry("proxmox_console")


def validate(value, request):
    action, params = request["action"], request["parameters"]
    if action == "discover":
        return spec.provider(value)
    if action in {"list", "status", "forget"}:
        common.validate(value, request)
        for row in value.get("results", []):
            spec.vmid(row["uuid"])
        return value
    if action == "console":
        spec.fields(value, {"uuid", "protocol", "audio", "authentication"})
        if (value["uuid"] != params["uuids"][0] or value["protocol"] != "vnc"
                or value["audio"] is not False or value["authentication"] != "rfb-password"):
            raise ValueError("The Proxmox console identity is invalid.")
        return value
    spec.fields(value, {"results", "digest"})
    frozen = {key: request[key] for key in ("connection", "profile", "provider")}
    frozen["intent"] = params["intent"]
    if value["digest"] != spec.digest(frozen):
        raise ValueError("Invalid Proxmox receipt digest.")
    rows = value["results"]
    expected = params["intent"]["expected"]
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError("Invalid Proxmox receipt count.")
    for item, target in zip(rows, expected, strict=True):
        spec.fields(item, {"uuid", "state"}, {"task", "error"})
        if item["uuid"] != target["uuid"] or item["state"] not in {"accepted", "refused", "unknown", "failed"}:
            raise ValueError("Invalid Proxmox receipt identity or outcome.")
        if "error" in item:
            common.response_error(item["error"])
        if "task" in item:
            spec.task(item["task"], node=request["provider"]["node"], expected_vmid=spec.vmid(item["uuid"]),
                      action=params["intent"]["action"])
        if item["state"] in {"accepted", "failed"} and "task" not in item:
            raise ValueError("The accepted Proxmox request requires its task identity.")
        if item["state"] == "failed" and (item["task"]["state"] != "stopped" or spec.task_succeeded(item["task"])):
            raise ValueError("A failed Proxmox request requires its exact failed task status.")
    return value


class Transport(common.Transport):
    async def request(self, node, profile, action, parameters, check):
        payload = {"version": 1, "action": action, "parameters": parameters}
        if action != "discover":
            payload.update(profile=profile["id"], connection="local", provider=profile["provider"])
        spec.request(payload)
        if self.pending >= 64:
            raise Failure("vm_busy", "The Proxmox request queue is full.", 429)
        self.pending += 1
        try:
            async with self.semaphore:
                check()
                code, output, stderr = await self.service.ssh.command(
                    node, COMMAND, spec.encode(payload), check=check,
                    timeout=spec.APPLY_TRANSPORT_SECONDS if action == "apply" else spec.TRANSPORT_SECONDS)
                check()
                if code:
                    if code == 42 or b"No module named" in stderr:
                        raise Failure("vm_helper_upgrade", "Install the current FICC node helper on this system.", 409)
                    raise transport_failure(stderr)
                try:
                    value = spec.decode(output)
                    spec.fields(value, {"version"}, {"data", "error"})
                    if type(value["version"]) is not int or value["version"] != 1 or ("data" in value) == ("error" in value):
                        raise ValueError("Invalid Proxmox response envelope.")
                    if "error" in value:
                        common.response_error(value["error"])
                        raise Failure(value["error"]["code"], value["error"]["message"], 409)
                    return validate(value["data"], payload)
                except (ValueError, TypeError, KeyError, RecursionError) as exc:
                    raise Failure("vm_invalid_response", "The Proxmox helper response is invalid.", 502) from exc
        finally:
            self.pending -= 1
