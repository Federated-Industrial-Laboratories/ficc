# SPDX-License-Identifier: Apache-2.0
"""Dispatch bounded resource and managed-job protocol requests."""

import json
import subprocess
import sys

from .collect import collect
from .job_system import capability


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--run-job":
        from .job_runner import run
        return run(sys.argv[2])
    request = {}
    try:
        raw = sys.stdin.buffer.readline(131073)
        if len(raw) > 131072:
            raise ValueError("Request exceeds the limit.")
        request = json.loads(raw)
        if request == {"version": "1", "action": "resources"}:
            result = collect()
            result["capabilities"].update(capability())
        else:
            from .jobs import dispatch
            result = {"version": "2", "result": dispatch(request)}
        print(json.dumps(result, allow_nan=False, separators=(",", ":")))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        uncertain = True
        if isinstance(request, dict) and request.get("action") == "job.submit":
            from .job_state import job_path
            try:
                uncertain = (job_path(request.get("job_id")) / "request.json").exists()
            except ValueError:
                uncertain = False
        print(json.dumps({"error": str(exc)[:240], "uncertain": uncertain}))
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
