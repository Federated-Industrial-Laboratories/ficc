# SPDX-License-Identifier: Apache-2.0
"""Validate package identity, runtime compatibility, capabilities and actions."""

import math
import re

from .adapter_manifest import validate_role
from .ui import validate_ui
from .validation import bounded, digest, fields, identifier, invalid, strings, text

CATEGORIES = {"virtual-machines", "containers", "system-administration", "productivity"}
HOST_CAPABILITIES = {"workspace:read", "workspace:write", "audio:playback"}
LANGUAGES = {"native": {"c", "cpp", "rust"}, "python": {"python"},
             "javascript": {"javascript", "typescript"}, "declarative": {"none"}}
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[a-z0-9.-]+)?\Z")
PATH_PART = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
CAPABILITY = re.compile(r"[a-z][a-z0-9-]{0,31}:[a-z][a-z0-9-]{0,31}\Z")


def package_path(value) -> str:
    result = text(value, 240)
    if not result or any(not PATH_PART.fullmatch(part) for part in result.split("/")):
        raise invalid("The module member path is invalid.")
    if any(part in {".", ".."} or part.endswith(".") for part in result.split("/")):
        raise invalid("The module member path is invalid.")
    return result


def capabilities(value) -> list[str]:
    result = strings(value, 32, 65)
    if any(not CAPABILITY.fullmatch(item) for item in result):
        raise invalid("The module capability name is invalid.")
    return result


def required_capabilities(manifest: dict) -> list[str]:
    """Return activation requirements; optional permissions still require grants to use."""
    optional = set(manifest.get("optional_capabilities", []))
    return [value for value in manifest["capabilities"] if value not in optional]


def validate_manifest(value) -> dict:
    bounded(value)
    fields(value, {"format_version", "id", "version", "category", "contract_version",
                   "host_api", "runtime", "capabilities", "dependencies", "actions", "ui", "files"},
           {"display_name", "description", "publisher", "optional_capabilities", "role", "adapter"})
    for key in ("format_version", "contract_version", "host_api"):
        if type(value[key]) is not int or value[key] != 1:
            raise invalid("The module format or host API version is unsupported.")
    identifier(value["id"])
    if not isinstance(value["version"], str) or len(value["version"]) > 64 or not VERSION.fullmatch(value["version"]):
        raise invalid("The module release version is invalid.")
    if not isinstance(value["category"], str) or value["category"] not in CATEGORIES:
        raise invalid("The module category is unsupported.")
    for key in ("display_name", "description", "publisher"):
        if key in value:
            text(value[key], 1024 if key == "description" else 160)
    capabilities(value["capabilities"])
    if set(capabilities(value.get("optional_capabilities", []))) - set(value["capabilities"]):
        raise invalid("An optional capability must be declared by the package.")
    if value["dependencies"] != []:
        raise invalid("Package dependencies are not supported. Include the required files.")
    runtime = fields(value["runtime"], {"kind", "language"}, {"entry", "platform", "architecture", "protocol"})
    kind = runtime["kind"]
    if (not isinstance(kind, str) or kind not in LANGUAGES
            or not isinstance(runtime["language"], str) or runtime["language"] not in LANGUAGES[kind]):
        raise invalid("The module runtime or source language is unsupported.")
    if kind == "declarative":
        fields(runtime, {"kind", "language"})
    else:
        fields(runtime, {"kind", "language", "entry", "platform", "architecture"}, {"protocol"})
        if type(runtime.get("protocol", 1)) is not int or runtime.get("protocol", 1) not in (1, 2):
            raise invalid("The module process protocol is unsupported.")
        package_path(runtime["entry"])
        if (runtime["platform"] != "linux" or not isinstance(runtime["architecture"], str)
                or runtime["architecture"] not in {"any", "x86_64", "aarch64"}):
            raise invalid("The module platform is unsupported.")
        if kind == "native" and runtime["architecture"] == "any":
            raise invalid("A native module requires an exact architecture.")
    inventory = value["files"]
    if not isinstance(inventory, dict) or len(inventory) > 255:
        raise invalid("The module file inventory exceeds the limit.")
    folded = set()
    for name, checksum in inventory.items():
        package_path(name)
        if name.casefold() == "manifest.json" or name.casefold() in folded:
            raise invalid("The module file inventory repeats a reserved name.")
        folded.add(name.casefold())
        digest(checksum)
    if kind != "declarative" and runtime["entry"] not in inventory:
        raise invalid("The module entry point is not in the file inventory.")
    actions = value["actions"]
    if not isinstance(actions, list) or len(actions) > 64:
        raise invalid("The module action list exceeds the limit.")
    names = set()
    for action in actions:
        fields(action, {"id", "parameters", "capabilities"}, {"label"})
        action_id = identifier(action["id"])
        if action_id in names:
            raise invalid("The module action is repeated.")
        names.add(action_id)
        if "label" in action:
            text(action["label"], 160)
        if set(capabilities(action["capabilities"])) - set(value["capabilities"]):
            raise invalid("The action requests an undeclared capability.")
        parameter_schema(action["parameters"])
    validate_ui(value["ui"], names, set(value["capabilities"]))
    validate_role(value)
    return value


def parameter_schema(value) -> None:
    if not isinstance(value, dict) or len(value) > 32:
        raise invalid("The module parameter schema exceeds the limit.")
    for name, spec in value.items():
        identifier(name)
        fields(spec, {"type"}, {"required", "max_length", "max_items", "min", "max", "choices"})
        if not isinstance(spec["type"], str) or spec["type"] not in {"string", "string-list", "integer", "number", "boolean"}:
            raise invalid("The module parameter type is unsupported.")
        if "required" in spec and type(spec["required"]) is not bool:
            raise invalid("The parameter required value must be boolean.")
        if "max_length" in spec and (spec["type"] not in {"string", "string-list"} or
                type(spec["max_length"]) is not int or not 1 <= spec["max_length"] <= 8192):
            raise invalid("The parameter length limit is invalid.")
        if "max_items" in spec and (spec["type"] != "string-list" or
                type(spec["max_items"]) is not int or not 1 <= spec["max_items"] <= 128):
            raise invalid("The parameter item count limit is invalid.")
        for bound in ("min", "max"):
            if bound in spec and (spec["type"] not in {"integer", "number"} or
                    type(spec[bound]) not in (int, float) or not math.isfinite(spec[bound])):
                raise invalid("The parameter numeric bound is invalid.")
        if "min" in spec and "max" in spec and spec["min"] > spec["max"]:
            raise invalid("The parameter bounds are reversed.")
        if "choices" in spec:
            if spec["type"] not in {"string", "string-list"}:
                raise invalid("Parameter choices require text values.")
            strings(spec["choices"], 64, 8192)


def validate_parameters(schema: dict, values) -> dict:
    bounded(values)
    if not isinstance(values, dict) or values.keys() - schema.keys():
        raise invalid("The module action parameters contain unknown fields.")
    for name, spec in schema.items():
        if name not in values:
            if spec.get("required", False):
                raise invalid("A required module parameter is missing.")
            continue
        item, kind = values[name], spec["type"]
        if kind == "string-list":
            strings(item, spec.get("max_items", 64), spec.get("max_length", 128))
            if "choices" in spec and set(item) - set(spec["choices"]):
                raise invalid("The module parameter contains an unavailable choice.")
        elif kind == "string":
            text(item, spec.get("max_length", 8192))
            if "choices" in spec and item not in spec["choices"]:
                raise invalid("The module parameter is not an available choice.")
        elif kind == "boolean":
            if type(item) is not bool:
                raise invalid("The module parameter must be boolean.")
        elif (type(item) not in (int, float) or not math.isfinite(item)
              or (kind == "integer" and type(item) is not int)
              or ("min" in spec and item < spec["min"])
              or ("max" in spec and item > spec["max"])):
            raise invalid("The module numeric parameter is invalid.")
    return values
