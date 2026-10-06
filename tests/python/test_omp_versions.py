# SPDX-License-Identifier: Apache-2.0
"""Accept both qualified OMP version formats, including launches with options."""

import sys

import pytest
from ficc_node.agents import probe


@pytest.mark.parametrize(("version", "delivery"), [
    ("omp/18.1.12", "direct"),
    ("omp v18.1.12", "direct"),
    ("omp 18.1.12", "direct"),
    ("18.1.12", "direct"),
    ("18.1.15", "inbox"),
])
def test_qualified_omp_version_output(tmp_path, version, delivery):
    executable = tmp_path / "runtime.py"
    executable.write_text(f"print({version!r})\n")
    profile = {"adapter": "omp", "argv": [sys.executable, str(executable)],
               "workspace": str(tmp_path)}
    result = probe(profile)
    assert result["version"] == version
    assert result["delivery_method"] == delivery
