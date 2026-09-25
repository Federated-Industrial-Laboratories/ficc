# SPDX-License-Identifier: Apache-2.0
"""Verify that publication checks detect exposed credentials and private state."""

import importlib.util
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[2] / "tools/check_source.py"
spec = importlib.util.spec_from_file_location("check_source", path)
assert spec and spec.loader
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


@pytest.mark.parametrize("payload", [
    "ghp_" + "a" * 36,
    "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    "/home/" + "local-owner" + "/private",
    "192." + "168.1.2",
    "10." + "4.8.2",
    "172." + "16.5.4",
    "172." + "31.255.8",
    "/home/" + "operator-private/project",
])
def test_detects_restricted_content(tmp_path, payload):
    (tmp_path / "README.md").write_text(payload)
    count, findings = checker.inspect(tmp_path)
    assert count == 1
    assert findings


def test_empty_tree_is_not_a_pass(tmp_path):
    assert checker.inspect(tmp_path)[1]


@pytest.mark.parametrize("example", ["rack-01 at 192.0.2.10", "127.0.0.1:8170", "/home/operator/project"])
def test_generic_documentation_passes(tmp_path, example):
    (tmp_path / "README.md").write_text("Example: " + example + "\n")
    assert checker.inspect(tmp_path) == (1, [])


def test_hidden_ci_directory_is_scanned(tmp_path):
    target = tmp_path / ".github" / "workflows"
    target.mkdir(parents=True)
    (target / "example.yml").write_text("credential: ghp_" + "a" * 36)
    assert checker.inspect(tmp_path)[1]
