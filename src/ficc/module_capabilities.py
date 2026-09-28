# SPDX-License-Identifier: Apache-2.0
"""Map implemented module permissions to owner-selected target types."""

from .errors import Failure

CAPABILITIES = {
    "workspace:read": {"kind": "workspace", "label": "Read workspace data"},
    "workspace:write": {"kind": "workspace", "label": "Save workspace data"},
    "audio:playback": {"kind": "workspace", "label": "Play audio in a workspace"},
    "files:read": {"kind": "folder", "label": "Read text in registered folders"},
    "files:write": {"kind": "folder", "label": "Save text in registered folders with retained recovery copies"},
    "system:read": {"kind": "system", "label": "Read saved system status and resource measurements"},
    "vm:read": {"kind": "system", "label": "Read VM inventory and state"},
    "vm:power": {"kind": "system", "label": "Start VMs and request graceful shutdown"},
    "vm:console": {"kind": "system", "label": "Open VM display and input"},
    "provider:admin": {"kind": "adapter-profile", "label": "Administer the complete registered provider account"},
    "container:read": {"kind": "system", "label": "Read container and workload inventory"},
    "container:logs": {"kind": "system", "label": "Read container and workload logs"},
    "container:power": {"kind": "system", "label": "Start or stop containers and scale workloads"},
    "admin:read": {"kind": "system", "label": "Read system and service status"},
    "admin:logs": {"kind": "system", "label": "Read service journal entries"},
    "admin:services": {"kind": "system", "label": "Start, stop or restart services"},
    "admin:power": {"kind": "system", "label": "Request system restart or shutdown"},
}
SUPPORTED = set(CAPABILITIES)


def require_target(service, capability, target):
    spec = CAPABILITIES.get(capability)
    if spec is None:
        raise Failure("module_capability_unavailable", "This module permission is not available.", 409)
    if spec["kind"] == "workspace":
        service.workspaces.get(target)
    elif spec["kind"] == "folder":
        service.files.store.root(target)
    elif spec["kind"] == "adapter-profile":
        service.adapters.records.profile(target)
    elif capability in {"vm:read", "vm:power", "vm:console"}:
        service.store.endpoint_kind(target)
    else:
        service.store.node(target)


def validate_instance(service, workspace_id, item):
    from .modules.manifest import HOST_CAPABILITIES, required_capabilities
    module = service.modules.get(item.digest)
    if module["manifest"].get("role") == "provider-adapter":
        raise Failure("module_role_invalid", "Provider adapters cannot be workspace panels.", 409)
    if not module["enabled"]:
        raise Failure("module_disabled", "Enable the module before adding or changing a panel.", 409)
    for capability in required_capabilities(module["manifest"]):
        targets = [workspace_id] if capability in HOST_CAPABILITIES else item.targets
        if not targets:
            raise Failure("module_targets_required", "Select targets for this module panel.", 409)
        for target in targets:
            require_target(service, capability, target)
        service.modules.require(item.digest, capability, targets)
    required_external = set(required_capabilities(module["manifest"])) - HOST_CAPABILITIES
    if not required_external:
        optional_external = set(module["manifest"]["capabilities"]) - HOST_CAPABILITIES
        for target in item.targets:
            for capability in optional_external:
                try:
                    require_target(service, capability, target)
                    service.modules.require(item.digest, capability, [target])
                    break
                except Failure:
                    continue
            else:
                raise Failure("module_target_denied", "The panel target has no current optional permission grant.", 403)


def catalogue(service, actor):
    principal = service.auth.current(actor)
    targets: dict[str, list[dict]] = {"workspace": [], "system": [], "folder": [], "adapter-profile": []}
    if "workspaces:read" in principal.scopes and principal.node_ids is None and principal.root_ids is None:
        targets["workspace"] = [{"id": value["id"], "name": value["name"]} for value in service.workspaces.all()]
    for value in service.store.nodes():
        try:
            principal.require("nodes:read", value["id"])
            targets["system"].append({"id": value["id"], "name": value["name"]})
        except Failure:
            pass
    from .module_windows_store import Records as WindowsRecords
    for value in WindowsRecords(service.store).all():
        try:
            principal.require("nodes:read", value["id"])
            targets["system"].append({"id": value["id"], "name": value["name"], "kind": "windows",
                                      "capabilities": ["vm:read", "vm:power", "vm:console"]})
        except Failure:
            pass
    for value in service.adapters.records.profiles():
        try:
            principal.require("providers:write", value["endpoint_id"])
            principal.require("nodes:read", value["endpoint_id"])
            targets["adapter-profile"].append({"id": value["id"], "name": value["id"],
                                                "digest": value["digest"], "endpoint_id": value["endpoint_id"]})
        except Failure:
            pass
    for root in service.files.registered():
        try:
            service.files.check(actor, "files:read", root)
            targets["folder"].append({"id": root["id"], "name": root["label"]})
        except Failure:
            pass
    return {"capabilities": CAPABILITIES, "targets": targets}
