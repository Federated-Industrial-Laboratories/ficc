# SPDX-License-Identifier: Apache-2.0
"""Read one bounded protocol request and return one resource sample."""

import json
import sys

from . import VERSION
from .collect import collect


def main() -> int:
    try:
        raw = sys.stdin.buffer.readline(8193)
        if len(raw) > 8192:
            raise ValueError("Request exceeds the limit.")
        request = json.loads(raw)
        if request != {"version": VERSION, "action": "resources"}:
            raise ValueError("Request is not supported.")
        print(json.dumps(collect(), allow_nan=False, separators=(",", ":")))
        return 0
    except (OSError, ValueError, KeyError):
        print(json.dumps({"error": "sample_unavailable"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
