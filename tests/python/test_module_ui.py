# SPDX-License-Identifier: Apache-2.0
"""Check component documents, literal paths, identities and sample packages."""

import copy
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from ficc.errors import Failure
from ficc.modules import protocol
from ficc.modules.manifest import validate_manifest
from ficc.modules.ui import validate_ui

ROOT = Path(__file__).resolve().parents[2]


def container(node):
    return {"type": "column", "children": [node]}


def table(count=1):
    return {"type": "table", "id": "items", "selection": "multiple", "page_size": 8,
            "columns": [{"id": "name", "label": "Name"}],
            "rows": [{"id": f"item-{index}", "values": {"name": f"Name {index}"}}
                     for index in range(count)]}


@pytest.mark.parametrize("count", [1, 64])
def test_stable_table_rows_and_selection_binding(count):
    ui = {"type": "column", "children": [table(count), {
        "type": "button", "action": "read", "parameters": {"ids": {"selection": "items"}}}]}
    assert validate_ui(ui, {"read"}, set()) is ui
    ui["children"][0]["rows"].reverse()
    assert validate_ui(ui, {"read"}, set()) is ui


@pytest.mark.parametrize("binding", [
    {"action": "unknown", "path": ["rows"]}, {"action": "read", "path": []},
    {"action": "read", "path": ["x"] * 9}, {"action": "read", "path": [True]},
    {"action": "read", "path": [256]}, {"action": "read", "path": [-1]},
    {"action": "read", "path": ["__proto__"]}, {"action": "read", "path": ["constructor"]},
    {"action": "read", "path": ["prototype"]}, {"action": "read", "path": ["x" * 97]},
    {"action": "read", "path": ["text"], "eval": "source"},
])
def test_binding_paths_are_literal_bounded_and_declared(binding):
    with pytest.raises(Failure):
        validate_ui(container({"type": "text", "bind": {"text": binding}}), {"read"}, set())


@pytest.mark.parametrize("node", [
    {"type": "field", "name": "constructor"},
    {"type": "text", "html": "<script>text</script>"},
    {"type": "text", "bind": {"html": {"action": "read", "path": ["text"]}}},
    {"type": "field", "name": "secret", "input_type": "password", "value": "text"},
    {"type": "credential", "name": "secret", "ref": "plaintext"},
    {"type": "credential", "name": "secret", "ref": "https://example.test"},
    {"type": "text", "state": "failed"}, {"type": "text", "disabled": 1},
    {"type": "status", "tone": "custom-style"}, {"type": "log", "lines": ["x"] * 129},
    {"type": "progress", "value": 101}, {"type": "meter", "value": float("nan")},
    {"type": "pager", "name": "page", "page": 0},
    {"type": "select", "name": "mode", "options": [], "value": []},
    {"type": "tree", "name": "tree", "items": [{"id": "a", "label": "A"}] * 2},
    {"type": "button", "action": "read", "parameters": {"ids": {"selection": "missing"}}},
    {"type": "button", "action": "read", "parameters": {"ids": {"field": "missing"}}},
])
def test_component_boundary_rejects_unsafe_or_invalid_values(node):
    with pytest.raises(Failure):
        validate_ui(container(node), {"read"}, set())


def test_reject_duplicate_rows_names_and_excessive_data():
    for value in (table(129), {**table(), "rows": table()["rows"] * 2}, {**table(), "page_size": 0}):
        with pytest.raises(Failure):
            validate_ui(container(value), set(), set())
    with pytest.raises(Failure):
        validate_ui({"type": "column", "children": [{"type": "field", "name": "same"}] * 2}, set(), set())
    with pytest.raises(Failure):
        validate_ui(container({"type": "text", "__proto__": {}}), set(), set())


def test_sample_source_builds_deterministically_with_complete_inventory(tmp_path):
    spec = importlib.util.spec_from_file_location("component_builder", ROOT / "tools/build-modules.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    manifest, files = builder.read_source(ROOT / "modules/component-gallery")
    archive = builder.publish(manifest, files, tmp_path)
    assert builder.publish(copy.deepcopy(manifest), files, tmp_path).read_bytes() == archive.read_bytes()
    assert manifest["capabilities"] == []
    assert set(files) == {"main.py", "ficc_module.py"}


@pytest.mark.parametrize("count", [1, 64])
def test_sample_runtime_returns_complete_bounded_batches(count):
    targets = [f"target-{index}" for index in range(count)]
    request_id, request = protocol.request("load", targets, {"count": count})
    process = subprocess.run(["/usr/bin/python3", "-I", str(ROOT / "modules/component-gallery/payload/main.py")],
                             input=request, capture_output=True, timeout=5, check=True)
    result = protocol.response(process.stdout, request_id, targets)
    assert not process.stderr
    assert [item["target"] for item in result["results"]] == targets
    for item in result["results"]:
        assert len(item["data"]["rows"]) == count
        assert [row["id"] for row in item["data"]["rows"]] == [f"sample-{index:03d}" for index in range(1, count + 1)]


@pytest.mark.parametrize("name", ["clock", "notes", "audio-player"])
def test_existing_declarative_default_documents_remain_valid(name):
    manifest = json.loads((ROOT / "modules" / name / "manifest.json").read_text())
    assert validate_manifest(manifest) == manifest
