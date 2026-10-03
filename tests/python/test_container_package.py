# SPDX-License-Identifier: Apache-2.0
"""Check supplied container packaging and N1/N64 declarative result bounds."""

import importlib.util
from pathlib import Path

import pytest

from ficc.modules.archive import inspect_archive
from ficc.modules.protocol import batch_results

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_supplied_container_archive_is_deterministic_and_optional():
    builder = load("container_builder", ROOT / "tools/build-modules.py")
    manifest, files = builder.read_source(ROOT / "modules/containers")
    files["ficc_module.py"] = (ROOT / "sdk/python/ficc_module.py").read_bytes()
    first = builder.build_archive(manifest, files)
    assert first == builder.build_archive(manifest, files)
    checked = inspect_archive(first)
    assert checked.manifest["optional_capabilities"] == ["container:logs", "container:power"]
    assert checked.manifest["runtime"]["protocol"] == 2
    assert {item["id"] for item in checked.manifest["actions"]} == {"load", "logs", "preview-start", "preview-stop", "preview-scale"}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_supplied_module_preserves_targets_selection_and_bounded_logs(count):
    module = load("container_payload", ROOT / "modules/containers/payload/main.py")
    targets = [f"node-{index}" for index in range(count)]
    calls = []
    def broker(primitive, selected, parameters):
        calls.append((primitive, selected, parameters))
        assert selected == targets
        if primitive == "container.preview":
            return [{"target": target, "data": {"preview_id": "a" * 32}} for target in selected]
        rows = []
        for index, target in enumerate(selected):
            pointer = {"kind": "container", "id": f"{index:064x}", "name": f"fixture-{index}", "namespace": ""}
            value = {"text": ("x" * 4096 + "\n") * 8, "truncated": True} if primitive == "container.logs" else {
                "resource": pointer, "state": "running", "replicas": None}
            rows.append({"target": target, "data": {"profiles": [{"provider": "docker", "data": {
                "truncated": False, "results": [{"resource_id": f"ctr-{'b' * 32}-container-{index:064x}", "resource": pointer, "data": value}]}}]}})
        return rows
    request = {"action": "load", "targets": targets, "parameters": {}}
    result = module.handle(request, broker)
    batch_results(result, targets)
    assert len(result[0]["data"]["rows"]) == count
    assert all(not item["data"]["rows"] for item in result[1:])
    selected = [item["id"] for item in result[0]["data"]["rows"]]
    request.update(action="logs", parameters={"resource_ids": selected})
    result = module.handle(request, broker)
    batch_results(result, targets)
    lines = result[0]["data"]["lines"]
    assert len(lines) <= 128 and all(len(line) <= 2048 for line in lines)
    assert "display limit" in lines[-1]
    request.update(action="preview-scale", parameters={"resource_ids": selected, "replicas": 0})
    result = module.handle(request, broker)
    batch_results(result, targets)
    assert calls[-1] == ("container.preview", targets, {"action": "scale", "resource_ids": selected, "replicas": 0})
    request["action"] = "commit"
    with pytest.raises(ValueError):
        module.handle(request, broker)
