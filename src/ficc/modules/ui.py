# SPDX-License-Identifier: Apache-2.0
"""Validate bounded host components, literal data paths and action parameters."""

import math

from .validation import bounded, fields, identifier, invalid, text

UNSAFE = {"__proto__", "prototype", "constructor"}
STATES = {"ready", "loading", "empty", "stale", "error"}
COMMON = {"id", "label", "disabled", "state", "message", "bind"}
PROPERTIES = {
    "column": {"children"}, "row": {"children"}, "group": {"children"},
    "toolbar": {"children"}, "menu": {"children"}, "tabs": {"items"},
    "text": {"text"}, "status": {"text", "tone"}, "details": {"items"},
    "button": {"action", "parameters"},
    "table": {"columns", "rows", "selection", "page_size"},
    "field": {"name", "value", "input_type"}, "credential": {"name", "ref"},
    "select": {"name", "value", "options"}, "radio": {"name", "value", "options"},
    "slider": {"name", "value", "min", "max", "step"},
    "progress": {"value", "max"}, "meter": {"value", "min", "max"},
    "tree": {"name", "items", "value"}, "pager": {"name", "page", "total"},
    "log": {"lines"}, "editor": {"ref", "value"}, "clock": {"timezone"},
    "audio-player": {"ref"}, "file-editor": set(),
}
BINDABLE = {
    "text": {"text"}, "status": {"text", "tone"}, "details": {"items"},
    "table": {"rows"}, "field": {"value"}, "select": {"value", "options"},
    "radio": {"value", "options"}, "slider": {"value"}, "progress": {"value"},
    "meter": {"value"}, "tree": {"items", "value"}, "pager": {"page", "total"},
    "log": {"lines"},
}


def _number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _name(value) -> str:
    result = identifier(value)
    if result in UNSAFE:
        raise invalid("The component identifier is reserved.")
    return result


def reference(value) -> str:
    result = text(value, 128)
    if not result or result in UNSAFE or any(char in result for char in "/\\:"):
        raise invalid("The component reference must be an opaque identifier.")
    return result


def _list(value, maximum: int) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        raise invalid("The component list exceeds the limit.")
    return value


def _choice(value, choices) -> None:
    if not isinstance(value, str) or value not in choices:
        raise invalid("The component choice is invalid.")


def _scalar(value, maximum: int = 4096) -> None:
    if isinstance(value, str):
        text(value, maximum)
    elif value is not None and type(value) is not bool and not _number(value):
        raise invalid("The component value must be a scalar.")


def _keys(value) -> None:
    if isinstance(value, dict):
        if value.keys() & UNSAFE:
            raise invalid("The component contains a reserved key.")
        for item in value.values():
            _keys(item)
    elif isinstance(value, list):
        for item in value:
            _keys(item)


def _bindings(node, actions: set[str]) -> None:
    bindings = node.get("bind", {})
    allowed = BINDABLE.get(node["type"], set()) | {"state", "message", "disabled"}
    if not isinstance(bindings, dict) or bindings.keys() - allowed:
        raise invalid("The component data binding is unsupported.")
    for binding in bindings.values():
        fields(binding, {"action", "path"})
        if not isinstance(binding["action"], str) or binding["action"] not in actions:
            raise invalid("The binding action is not declared.")
        path = _list(binding["path"], 8)
        if not path:
            raise invalid("The data path must not be empty.")
        for key in path:
            if type(key) is int and 0 <= key < 256:
                continue
            if not isinstance(key, str) or not text(key, 96) or key in UNSAFE:
                raise invalid("The data path key is invalid.")


def _options(node) -> None:
    ids: set[str] = set()
    for item in _list(node.get("options", []), 64):
        fields(item, {"id", "label"}, {"disabled"})
        value = reference(item["id"])
        if value in ids:
            raise invalid("The component option is repeated.")
        ids.add(value)
        text(item["label"], 160)
        if "disabled" in item and type(item["disabled"]) is not bool:
            raise invalid("The option disabled value must be boolean.")
    if node.get("value", "") != "" and reference(node["value"]) not in ids:
        raise invalid("The selected option is not available.")


def _tree(node) -> None:
    ids: set[str] = set()

    def walk(items, depth=0):
        if depth > 6:
            raise invalid("The tree depth exceeds the limit.")
        for item in _list(items, 128):
            fields(item, {"id", "label"}, {"children"})
            value = reference(item["id"])
            if value in ids or len(ids) >= 128:
                raise invalid("The tree identifier is repeated or exceeds the limit.")
            ids.add(value)
            text(item["label"], 160)
            walk(item.get("children", []), depth + 1)

    walk(node.get("items", []))
    if node.get("value", "") != "" and reference(node["value"]) not in ids:
        raise invalid("The selected tree item is not available.")


def table(node) -> None:
    columns, rows = node.get("columns", []), node.get("rows", [])
    if not _list(columns, 32):
        raise invalid("The module table columns are invalid.")
    ids: set[str] = set()
    for column in columns:
        fields(column, {"id", "label"})
        column_id = _name(column["id"])
        if column_id in ids:
            raise invalid("The module table column is repeated.")
        ids.add(column_id)
        text(column["label"], 160)
    row_ids = set()
    for row in _list(rows, 128):
        fields(row, {"id", "values"})
        row_id = reference(row["id"])
        if row_id in row_ids:
            raise invalid("The module table row is repeated.")
        row_ids.add(row_id)
        if not isinstance(row["values"], dict) or row["values"].keys() - ids:
            raise invalid("The table row has an unknown column.")
        for item in row["values"].values():
            _scalar(item)
    _choice(node.get("selection", "none"), {"none", "single", "multiple"})
    if node.get("selection", "none") != "none" and "id" not in node:
        raise invalid("A table selection requires a component identifier.")
    page = node.get("page_size", 16)
    if type(page) is not int or not 1 <= page <= 128:
        raise invalid("The table page size is invalid.")


def _data(node) -> None:
    kind = node["type"]
    if kind in {"text", "status"}:
        text(node.get("text", ""), 8192)
        if kind == "status":
            _choice(node.get("tone", "neutral"), {"neutral", "good", "warning", "error"})
    elif kind == "table":
        table(node)
    elif kind == "details":
        for item in _list(node.get("items", []), 64):
            fields(item, {"label", "value"})
            text(item["label"], 160)
            _scalar(item["value"])
    elif kind == "field":
        input_type, item = node.get("input_type", "text"), node.get("value", "")
        if input_type == "text":
            text(item, 8192)
        elif not (input_type == "number" and _number(item) or
                  input_type == "checkbox" and type(item) is bool):
            raise invalid("The component field value is invalid.")
    elif kind in {"slider", "progress", "meter"}:
        low, high, value = node.get("min", 0), node.get("max", 100), node.get("value", 0)
        if not all(_number(item) for item in (low, high, value)) or low >= high or not low <= value <= high:
            raise invalid("The component numeric bounds are invalid.")
        if kind == "slider" and (not _number(node.get("step")) or node["step"] <= 0):
            raise invalid("The component slider step is invalid.")
    elif kind in {"select", "radio"}:
        _options(node)
    elif kind == "tree":
        _tree(node)
    elif kind == "pager":
        page, total = node.get("page", 1), node.get("total", 1)
        if type(page) is not int or type(total) is not int or not 1 <= page <= total <= 128:
            raise invalid("The component page bounds are invalid.")
    elif kind == "log":
        for line in _list(node.get("lines", []), 128):
            text(line, 2048)
    elif kind in {"editor", "audio-player", "credential"}:
        if "ref" in node:
            reference(node["ref"])
        if kind == "credential" and not node.get("ref", "").startswith("hostcredential-"):
            raise invalid("The credential requires a host credential reference.")
        if kind == "editor":
            text(node.get("value", ""), 65536)
    elif kind == "clock":
        text(node.get("timezone", "UTC"), 128)


def validate_ui(value, actions: set[str], capabilities: set[str]) -> dict:
    bounded(value)
    _keys(value)
    count = 0
    ids: set[str] = set()
    names: set[str] = set()
    selections: set[str] = set()
    parameters = []

    def component(node, depth: int = 0):
        nonlocal count
        count += 1
        if count > 128 or depth > 8 or not isinstance(node, dict):
            raise invalid("The module component tree exceeds the limit.")
        kind = node.get("type")
        if not isinstance(kind, str) or kind not in PROPERTIES:
            raise invalid("The module component type is unsupported.")
        required = {"file-editor": {"workspace:read", "files:read"},
                    "editor": {"workspace:read", "workspace:write"},
                    "audio-player": {"workspace:read", "workspace:write", "audio:playback"}}.get(kind, set())
        if required - capabilities:
            raise invalid("The module component requires undeclared host capabilities.")
        fields(node, {"type"}, COMMON | PROPERTIES[kind])
        if kind == "file-editor":
            _name(node.get("id"))
        if "id" in node:
            value_id = _name(node["id"])
            if value_id in ids:
                raise invalid("The module component identifier is repeated.")
            ids.add(value_id)
        if "name" in PROPERTIES[kind]:
            name = _name(node.get("name"))
            if name in names:
                raise invalid("The component field name is repeated.")
            names.add(name)
        if "label" in node:
            text(node["label"], 160)
        if "message" in node:
            text(node["message"], 160)
        if "state" in node:
            _choice(node["state"], STATES)
        if "disabled" in node and type(node["disabled"]) is not bool:
            raise invalid("The component disabled value must be boolean.")
        _bindings(node, actions)
        if kind in {"column", "row", "group", "toolbar", "menu"}:
            for child in _list(node.get("children", []), 32):
                component(child, depth + 1)
        elif kind == "tabs":
            tab_ids = set()
            items = _list(node.get("items", []), 16)
            if not items:
                raise invalid("A tab group requires at least one tab.")
            for item in items:
                fields(item, {"id", "label", "children"})
                name = _name(item["id"])
                if name in tab_ids:
                    raise invalid("The tab identifier is repeated.")
                tab_ids.add(name)
                text(item["label"], 160)
                for child in _list(item["children"], 32):
                    component(child, depth + 1)
        elif kind == "button":
            if not isinstance(node.get("action"), str) or node["action"] not in actions:
                raise invalid("The component action is not declared.")
            if "parameters" in node:
                parameters.append(node["parameters"])
        else:
            _data(node)
            if kind == "table" and node.get("selection", "none") != "none":
                selections.add(node["id"])

    component(value)
    if value["type"] not in {"column", "row", "group", "tabs"}:
        raise invalid("The module view requires a container root.")
    for mapping in parameters:
        if not isinstance(mapping, dict) or len(mapping) > 32:
            raise invalid("The component parameter map exceeds the limit.")
        for name, source in mapping.items():
            _name(name)
            if not isinstance(source, dict) or len(source) != 1:
                raise invalid("The component parameter source is invalid.")
            if "field" in source:
                if _name(source["field"]) not in names:
                    raise invalid("The parameter field is not declared.")
            elif "selection" in source:
                if _name(source["selection"]) not in selections:
                    raise invalid("The parameter selection is not declared.")
            elif "value" in source:
                _scalar(source["value"], 8192)
            else:
                raise invalid("The component parameter source is unsupported.")
    return value
