# SPDX-License-Identifier: Apache-2.0
"""Read a complete system batch through the host capability broker."""
import runpy
from pathlib import Path

serve_broker = runpy.run_path(str(Path(__file__).with_name('ficc_module.py')))['serve_broker']


def resources(request, broker):
    if request['action'] != 'read':
        return [{'target': target, 'error': {'code': 'unsupported_action', 'message': 'Select the read action.'}}
                for target in request['targets']]
    return broker('system.resources.read', request['targets'], {})


raise SystemExit(serve_broker(resources))
