# SPDX-License-Identifier: Apache-2.0
"""Dispatch bounded resource, job, file and terminal protocol requests."""

import json
import os
import subprocess
import sys

from .collect import collect
from .job_system import capability


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--run-job":
        from .job_runner import run
        return run(sys.argv[2])
    if len(sys.argv) == 4 and sys.argv[1] == "--attach-terminal":
        from .terminals import attach
        attach(sys.argv[2], sys.argv[3])
        return 0
    request = {}
    try:
        raw = sys.stdin.buffer.readline(131073)
        if len(raw) > 131072:
            raise ValueError("Request exceeds the limit.")
        request = json.loads(raw)
        if request == {"version": "1", "action": "resources"}:
            result = collect()
            result["capabilities"].update(capability())
            import shutil

            from .file_access import opened
            try:
                fd = opened(-100, b"/", os.O_RDONLY | os.O_DIRECTORY, False)
                os.close(fd)
                files_available = True
            except (OSError, ValueError):
                files_available = False
            result["capabilities"].update(terminals=True, terminals_ephemeral=True, terminals_tmux=bool(shutil.which("tmux")),
                                          files=files_available)
        elif isinstance(request, dict) and request.get("version") == "3":
            if str(request.get("action", "")).startswith("terminal."):
                from .terminals import dispatch as terminal_dispatch
                result = {"version": "3", "result": terminal_dispatch(request)}
            else:
                from .file_access import FileError
                from .files import dispatch as file_dispatch
                length = request.get("data_length", 0)
                if type(length) is not int or not 0 <= length <= 262144 or len(raw) > 65536:
                    raise ValueError("Invalid file request length.")
                data = sys.stdin.buffer.read(length + 1)
                if len(data) != length:
                    raise ValueError("Invalid file request body.")
                try:
                    header, data = file_dispatch(request, data)
                    result = {"version": "3", "result": header, "data_length": len(data)}
                except FileError as exc:
                    sys.stdout.buffer.write(json.dumps({"version": "3", "error": {
                        "code": exc.code, "message": exc.message}, "data_length": 0}).encode() + b"\n")
                    return 65
                sys.stdout.buffer.write(json.dumps(result, allow_nan=False).encode() + b"\n" + data)
                return 0
        else:
            from .jobs import dispatch
            result = {"version": "2", "result": dispatch(request)}
        print(json.dumps(result, allow_nan=False, separators=(",", ":")))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        if (isinstance(request, dict) and request.get("version") == "3"
                and not str(request.get("action", "")).startswith("terminal.")):
            print(json.dumps({"version": "3", "error": {"code": "file_unavailable",
                              "message": "The file action could not be completed."}, "data_length": 0}))
            return 65
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
