# SPDX-License-Identifier: Apache-2.0
"""Serve the installed Hyper-V provider package in the controller sandbox."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ficc_adapter import serve  # noqa: E402
from hyperv import handle  # noqa: E402

raise SystemExit(serve(handle))
