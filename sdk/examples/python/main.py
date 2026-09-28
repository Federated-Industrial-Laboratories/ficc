# SPDX-License-Identifier: Apache-2.0
"""Return one echo result for every requested target."""

import runpy
from pathlib import Path

# Isolated Python does not add the package directory to its import path.
serve = runpy.run_path(str(Path(__file__).with_name("ficc_module.py")))["serve"]


def echo(request):
    message = request["parameters"].get("message")
    if request["action"] != "echo" or not isinstance(message, str):
        return [{"target": target, "error": {"code": "unsupported_action",
                 "message": "Select the echo action and supply a message."}}
                for target in request["targets"]]
    return [{"target": target, "data": {"message": message, "index": index}}
            for index, target in enumerate(request["targets"])]


raise SystemExit(serve(echo))
