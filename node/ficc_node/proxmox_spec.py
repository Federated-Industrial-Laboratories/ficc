# SPDX-License-Identifier: Apache-2.0
"""Validate fixed local Proxmox requests and stable provider identities."""

import copy
import re
import uuid

from . import vm_spec as common

fields, identity, fingerprint = common.fields, common.identity, common.fingerprint
integer, text, uuids = common.integer, common.text, common.uuids
encode, decode, digest = common.encode, common.decode, common.digest
STATES, MAX_MESSAGE = common.STATES, common.MAX_MESSAGE
TERMINAL = common.TERMINAL | {"failed"}
REQUEST_SECONDS, APPLY_SECONDS = 6, 12
TRANSPORT_SECONDS, APPLY_TRANSPORT_SECONDS = 8, 14
BRIDGE_SECONDS = 4.5
CONNECTIONS = {"local": "Proxmox local root API"}
RESOURCE = re.compile(r"proxmox-([0-9a-f]{32})-([0-9a-f]{32})\Z")
NODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}\Z")
UPID = re.compile(r"UPID:([A-Za-z0-9][A-Za-z0-9-]{0,62}):[0-9A-F]{8}:[0-9A-F]{8,16}:[0-9A-F]{8}:ficcvm(start|shutdown):([1-9][0-9]{2,8}):root@pam:\Z")


def resource(value):
    found = RESOURCE.fullmatch(value) if isinstance(value, str) else None
    if found is None:
        raise ValueError("Invalid Proxmox resource identity.")
    return found.groups()


def provider(value):
    fields(value, {"version", "fingerprint", "node", "machine_id"})
    version = text(value["version"], 96)
    if not re.fullmatch(r"pve-manager/9\.2\.\d+/[0-9a-f]{8,64}", version):
        raise ValueError("This adapter requires a qualified Proxmox 9.2 build.")
    fingerprint(value["fingerprint"])
    identity(value["machine_id"])
    if not isinstance(value["node"], str) or not NODE.fullmatch(value["node"]):
        raise ValueError("Invalid Proxmox node identity.")
    return value


def birth(vmid, smbios, generation, machine_id):
    integer(vmid, 100, 999999999)
    identity(machine_id)
    values = []
    for value in (smbios, generation):
        if not isinstance(value, str) or len(value) != 36:
            raise ValueError("Both provider-created UUIDs are required.")
        parsed = uuid.UUID(value)
        if str(parsed) != value.lower() or parsed.int == 0:
            raise ValueError("Invalid provider-created UUID.")
        values.append(parsed.hex)
    # The numeric prefix permits bounded lookups without scanning every VM config.
    return f"{vmid:08x}" + digest({"machine": machine_id, "smbios": values[0], "generation": values[1]})[:24]


def vmid(value):
    identity(value)
    return integer(int(value[:8], 16), 100, 999999999)


def task(value, *, node=None, expected_vmid=None, action=None):
    fields(value, {"upid", "state"}, {"exitstatus"})
    found = UPID.fullmatch(value["upid"]) if isinstance(value["upid"], str) else None
    if (found is None or node is not None and found[1] != node
            or action is not None and found[2] != action
            or expected_vmid is not None and int(found[3]) != expected_vmid):
        raise ValueError("The provider task identity does not match this VM action.")
    if value["state"] not in {"running", "stopped", "unknown"}:
        raise ValueError("Invalid provider task state.")
    if "exitstatus" in value:
        text(value["exitstatus"], 256)
        if value["state"] != "stopped":
            raise ValueError("A task exit status requires a stopped task.")
    elif value["state"] == "stopped":
        raise ValueError("A stopped provider task requires its exit status.")
    return value


def task_succeeded(value):
    return value["state"] == "stopped" and (value["exitstatus"] == "OK"
        or re.fullmatch(r"WARNINGS: [1-9][0-9]{0,5}", value["exitstatus"]) is not None)


def request(value):
    if isinstance(value, dict) and value.get("action") == "discover":
        fields(value, {"version", "action", "parameters"})
        fields(value["parameters"], set())
        if type(value["version"]) is not int or value["version"] != 1:
            raise ValueError("Unsupported Proxmox protocol version.")
        return value
    fields(value, {"version", "action", "connection", "profile", "provider", "parameters"})
    if value["connection"] != "local":
        raise ValueError("Only the fixed local Proxmox API is supported.")
    provider(value["provider"])
    validated = copy.deepcopy({key: item for key, item in value.items() if key != "provider"})
    validated["connection"] = "system"
    if value["action"] == "forget" and isinstance(validated["parameters"], dict):
        outcomes = validated["parameters"].get("outcomes")
        if isinstance(outcomes, list):
            for item in outcomes:
                if isinstance(item, dict) and item.get("state") == "failed":
                    item["state"] = "resolved"
    common.request(validated)
    params = value["parameters"]
    selected = params.get("uuids", [item["uuid"] for item in params.get("intent", {}).get("expected", [])])
    for selected_id in selected:
        vmid(selected_id)
    return value
