# SPDX-License-Identifier: Apache-2.0
"""Separate provider account authority from ordinary workspace module actions."""

from .validation import fields, invalid, strings

ROLE = "provider-adapter"
ADMIN = "provider:admin"
CONSISTENCY = {"provider-lock", "checked-before-dispatch"}
TRANSPORTS = {("enrolled-node", "local-ipc"), ("controller", "winrm-jea")}
OPERATIONS = {"inventory", "status", "start", "shutdown", "console"}


def validate_role(manifest: dict) -> None:
    """Require explicit account administration for an isolated provider adapter."""
    role = manifest.get("role", "module")
    if role == "module":
        if "adapter" in manifest or ADMIN in manifest["capabilities"]:
            raise invalid("A workspace module cannot request provider account access.")
        return
    if role != ROLE:
        raise invalid("The module role is unsupported.")
    if manifest["category"] != "virtual-machines":
        raise invalid("The provider adapter category is unsupported.")
    if (manifest["capabilities"] != [ADMIN] or manifest.get("optional_capabilities", [])
            or manifest["actions"] or manifest["ui"] != {"type": "column", "children": []}):
        raise invalid("A provider adapter requires separate account access and has no workspace actions.")
    runtime = manifest["runtime"]
    if runtime["kind"] == "declarative" or runtime.get("protocol", 1) != 1:
        raise invalid("A provider adapter requires its version-one executable protocol.")
    adapter = fields(manifest.get("adapter"), {"version", "family", "execution", "transport",
                                             "consistency", "operations"})
    if type(adapter["version"]) is not int or adapter["version"] != 1:
        raise invalid("The provider adapter contract version is unsupported.")
    if adapter["family"] != "virtual-machines":
        raise invalid("The provider adapter family is unsupported.")
    if (not isinstance(adapter["execution"], str) or not isinstance(adapter["transport"], str)
            or (adapter["execution"], adapter["transport"]) not in TRANSPORTS):
        raise invalid("The provider adapter transport is unsupported.")
    if not isinstance(adapter["consistency"], str) or adapter["consistency"] not in CONSISTENCY:
        raise invalid("The provider adapter consistency class is unsupported.")
    operations = set(strings(adapter["operations"], 5, 32))
    if not {"inventory", "status"} <= operations or operations - OPERATIONS:
        raise invalid("The provider adapter operation set is unsupported.")
