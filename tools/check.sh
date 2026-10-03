#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run source, Python and type checks from the project root.
# Inputs: active Python environment. Output: check results. Exit: first failure.
set -euo pipefail
cd "$(dirname "$0")/.."
python tools/check_source.py
python -m ruff check --no-respect-gitignore src node tests tools *-providers/*/src policy-providers/opa/tests identity-providers/oidc/tests packaging/remote/keycloak packaging/remote/executor
python -m mypy
MYPYPATH=src:node python -m mypy *-providers/*/src
python -m pytest
