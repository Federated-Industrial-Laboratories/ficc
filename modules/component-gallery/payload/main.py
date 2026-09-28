# SPDX-License-Identifier: Apache-2.0
"""Return sample component data without a provider or host resource call."""

import runpy
from pathlib import Path

serve = runpy.run_path(str(Path(__file__).with_name("ficc_module.py")))["serve"]


def gallery(request):
    parameters = request["parameters"]
    if request["action"] == "load":
        count = parameters["count"]
        data = {
            "rows": [{"id": f"sample-{index:03d}", "values": {
                "name": f"Sample {index}", "value": index, "state": "Ready"}}
                for index in range(1, count + 1)],
            "text": f"Loaded {count} sample rows.", "state": "ready", "value": count,
            "lines": [f"Sample row {index} is ready." for index in range(1, count + 1)],
            "details": [{"label": "Source", "value": "Sample data"}, {"label": "Rows", "value": count}],
        }
    elif request["action"] == "select":
        data = {"text": "Selected: " + (", ".join(parameters["selected"]) or "none")}
    else:
        return [{"target": target, "error": {"code": "unsupported_action",
                 "message": "Select a supported sample action."}} for target in request["targets"]]
    return [{"target": target, "data": data} for target in request["targets"]]


raise SystemExit(serve(gallery))
