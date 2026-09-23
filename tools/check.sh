#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run source, Python and type checks from the project root.
# Inputs: active Python environment. Output: check results. Exit: first failure.
set -euo pipefail
cd "$(dirname "$0")/.."
python tools/check_source.py
python -m ruff check src node tests tools
python -m mypy
python -m pytest
