#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Install the current source for this account; inputs: options; exit: zero on success.
set -eu
cd -- "$(dirname -- "$0")"
exec python3 tools/install_source.py "$@"
