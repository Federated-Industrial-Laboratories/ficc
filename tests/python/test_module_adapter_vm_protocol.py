# SPDX-License-Identifier: Apache-2.0
"""Refuse malformed provider rows and substituted complete-batch outcomes."""

import copy

import pytest
from test_module_adapter_protocol import bindings
from test_module_adapter_store import operation

from ficc.errors import Failure
from ficc.modules.adapter_vm_protocol import result


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("change", ["missing", "duplicate", "birth", "identity", "extra", "name", "cpu", "console"])
def test_status_requires_exact_birth_and_complete_bounded_rows(count, change):
    resources = [target["resource"] for target in operation(count)["targets"]]
    binding = {**bindings()[0], "resources": resources}
    rows = [{"id": resource["id"], "data": {"resource": copy.deepcopy(resource), "name": "Guest",
        "memory_kib": 65536, "vcpus": 1, "console": True}} for resource in resources]
    assert result({"results": rows}, "status", "status", binding)
    if change == "missing":
        rows.pop()
    elif change == "duplicate":
        rows[-1]["id"] = "9" * 32
    elif change == "birth":
        rows[-1]["data"]["resource"]["birth"] = "9" * 64
    elif change == "identity":
        rows[-1]["data"]["resource"]["id"] = "9" * 32
    elif change == "extra":
        rows[-1]["data"]["password"] = "must-not-pass"
    elif change == "name":
        rows[-1]["data"]["name"] = "x" * 257
    elif change == "cpu":
        rows[-1]["data"]["vcpus"] = True
    else:
        rows[-1]["data"]["console"] = "yes"
    with pytest.raises(Failure):
        result({"results": rows}, "status", "status", binding)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("change", ["task", "completion", "refused", "order", "partial"])
def test_receipt_requires_exact_task_proof_and_complete_order(count, change):
    resources = [target["resource"] for target in operation(count)["targets"]]
    binding = {**bindings()[0], "resources": resources}
    rows = [{"id": resource["id"], "receipt": {"state": "accepted", "token": {"task": resource["id"]},
        "completed": False, "result": "unknown"}} for resource in resources]
    assert result({"results": rows}, "apply", "start", binding)
    if change == "task":
        rows[-1]["receipt"]["token"] = {}
    elif change == "completion":
        rows[-1]["receipt"]["state"] = "observed"
    elif change == "refused":
        rows[-1]["receipt"].update(state="refused", completed=True, result="failure")
    elif change == "order":
        rows[-1]["id"] = "9" * 32
    else:
        rows.pop()
    with pytest.raises(Failure):
        result({"results": rows}, "apply", "start", binding)


@pytest.mark.parametrize("task,completed,token", [("active", True, {"job": "x"}),
    ("unknown", True, {"job": "x"}), ("finished", False, {"job": "x"}), ("active", False, {}), ("other", False, {})])
def test_task_ownership_cannot_disagree_with_completion(task, completed, token):
    from ficc.modules.adapter_vm_protocol import receipt
    with pytest.raises(Failure, match="task ownership"):
        receipt({"state": "unknown", "token": token, "completed": completed, "result": "unknown", "task_state": task})
