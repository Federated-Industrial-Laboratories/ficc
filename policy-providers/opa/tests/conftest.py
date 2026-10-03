# SPDX-License-Identifier: Apache-2.0
"""Create private policy inputs for contract and real evaluator tests."""

import json
import os
import tempfile
from pathlib import Path

import pytest

POLICY = '''package ficc
decisions := [{"id": item.id, "allow": permitted(item), "reason": code(item)} |
    item := input.requests[_]]
permitted(item) := item.authority.project == data.settings.project
code(item) := "allowed" if permitted(item)
code(item) := "denied" if not permitted(item)
'''
DIGEST = "668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"


def envelope(count: int, denied: bool = False) -> dict:
    return {"version": 1, "revision": 19, "requests": [
        {"id": f"request-{index}", "action": "nodes.read",
         "authority": {"project": "allowed" if index % 2 == 0 and not denied else f"other-{index}",
                       "identity": f"user-{index}"},
         "labels": {"user_text": f"untrusted-{index}", "project": "allowed"}}
        for index in range(count)]}


@pytest.fixture
def paths():
    with tempfile.TemporaryDirectory(prefix="ficc-opa-") as name:
        root = Path(name)
        source, run = root / "source", root / "run"
        source.mkdir(mode=0o700)
        run.mkdir(mode=0o700)
        (source / "rules.rego").write_text(POLICY)
        (source / "data.json").write_text(json.dumps({"settings": {"project": "allowed"}}))
        for path in source.iterdir():
            path.chmod(0o600)
        yield source, run


@pytest.fixture
def configuration():
    value = os.environ.get("FICC_TEST_OPA")
    if not value:
        pytest.skip("Set FICC_TEST_OPA to the official OPA 1.21.1 static binary for real isolation tests.")
    return {"binary": str(Path(value).absolute()), "sha256": DIGEST}
