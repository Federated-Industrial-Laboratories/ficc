# SPDX-License-Identifier: Apache-2.0
"""Map implemented module permissions to owner-selected target types."""

from .errors import Failure
from .modules.manifest import HOST_CAPABILITIES, required_capabilities

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
PROJECT_CAPABILITIES = SUPPORTED - {"provider:admin"}


def actor_requirements(service, principal, capability, target):
    """Resolve one package capability to its project and resource checks."""
    if capability not in PROJECT_CAPABILITIES:
        raise Failure("denied", "This module permission requires installation administration.", 403)
    if capability in HOST_CAPABILITIES:
        scope = {"workspace:read": "workspaces:read", "workspace:write": "workspaces:write",
                 "audio:playback": "audio:playback"}[capability]
        service.workspaces.scoped(principal).get(target)
        return [(scope, None, None)]
    elif CAPABILITIES[capability]["kind"] == "folder":
        service.files.check(principal.id, capability, service.files.store.root(target))
        return []
    return [("nodes:read", target, None),
            ("resources:read" if capability == "system:read" else capability, target, None)]


def require_actor_target(service, principal, capability, target):
    """Intersect one package capability with current project and resource authority."""
    requirements = actor_requirements(service, principal, capability, target)
    for scope, node, root in requirements:
        principal.require_host(scope, node, root)
    service.policies.check_many(principal, requirements)


def project_modules(service, principal):
    """Expose enabled packages with only currently usable project grants."""
    values = []
    workspaces = {item["id"] for item in service.workspaces.scoped(principal).all()}
    for module in service.modules.list():
        if not module["enabled"] or module["manifest"].get("role", "module") != "module":
            continue
        grants = []
        for grant in module["grants"]:
            selected = []
            for target in grant["target_ids"]:
                if grant["capability"] in HOST_CAPABILITIES and target not in workspaces:
                    continue
                try:
                    require_actor_target(service, principal, grant["capability"], target)
                    selected.append(target)
                except Failure as exc:
                    if exc.status not in {403, 404}:
                        raise
            if selected:
                grants.append({**grant, "target_ids": selected})
        available = {grant["capability"] for grant in grants}
        if "workspace:read" in available and set(required_capabilities(module["manifest"])) <= available:
            values.append({**module, "grants": grants})
    return values


def require_action(service, principal, workspace_id, instance, action, targets):
    """Recheck project and package authority throughout one selected action."""
    requirements = [("modules:execute", None, None), ("workspaces:read", None, None)]
    if principal.local_owner:
        service.policies.check_many(principal, requirements)
        return
    manifest = service.modules.get(instance["digest"])["manifest"]
    if manifest.get("role", "module") != "module":
        raise Failure("module_role_invalid", "Provider adapters cannot be workspace panels.", 409)
    grants = [("workspace:read", [workspace_id])]
    selected = next((item for item in manifest["actions"] if item["id"] == action), None)
    capabilities = set(required_capabilities(manifest)) | set(selected["capabilities"] if selected else [])
    for capability in capabilities:
        checked = [workspace_id] if capability in HOST_CAPABILITIES else targets
        for target in checked:
            requirements.extend(actor_requirements(service, principal, capability, target))
        grants.append((capability, checked))
    service.modules.require_many(instance["digest"], grants)
    service.policies.check_many(principal, requirements)


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


def validate_instance(service, workspace_id, item, principal=None):
    module = service.modules.get(item.digest)
    if module["manifest"].get("role") == "provider-adapter":
        raise Failure("module_role_invalid", "Provider adapters cannot be workspace panels.", 409)
    if not module["enabled"]:
        raise Failure("module_disabled", "Enable the module before adding or changing a panel.", 409)
    if principal is not None and not principal.local_owner:
        service.modules.require(item.digest, "workspace:read", [workspace_id])
    for capability in required_capabilities(module["manifest"]):
        targets = [workspace_id] if capability in HOST_CAPABILITIES else item.targets
        if not targets:
            raise Failure("module_targets_required", "Select targets for this module panel.", 409)
        for target in targets:
            require_target(service, capability, target)
            if principal is not None and not principal.local_owner:
                require_actor_target(service, principal, capability, target)
        service.modules.require(item.digest, capability, targets)
    required_external = set(required_capabilities(module["manifest"])) - HOST_CAPABILITIES
    if not required_external:
        optional_external = set(module["manifest"]["capabilities"]) - HOST_CAPABILITIES
        for target in item.targets:
            for capability in optional_external:
                try:
                    require_target(service, capability, target)
                    if principal is not None and not principal.local_owner:
                        require_actor_target(service, principal, capability, target)
                    service.modules.require(item.digest, capability, [target])
                    break
                except Failure:
                    continue
            else:
                raise Failure("module_target_denied", "The panel target has no current optional permission grant.", 403)


def catalogue(service, actor):
    with service.store.lock:
        return scoped_catalogue(service, actor)


def scoped_catalogue(service, actor):
    principal = service.auth.current(actor)
    targets: dict[str, list[dict]] = {"workspace": [], "system": [], "folder": [], "adapter-profile": []}
    if principal.node_ids is None and principal.root_ids is None and principal.permits("workspaces:read"):
        for value in service.workspaces.scoped(principal).all():
            targets["workspace"].append({"id": value["id"], "name": value["name"]})
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
    capabilities = CAPABILITIES if principal.local_owner else {
        key: value for key, value in CAPABILITIES.items() if key in PROJECT_CAPABILITIES}
    return {"capabilities": capabilities, "targets": targets}
