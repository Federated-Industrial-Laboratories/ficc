# SPDX-License-Identifier: Apache-2.0
"""Common controller GPU exclusion across SSH jobs and contributor execution."""
from ficc_node.job_spec import TERMINAL

from ..errors import Failure


def require_free(store, devices, *, workload=False):
    devices = set(devices)
    if not devices:
        return
    from ..job_store import JobStore
    from ..workloads.records import Records
    if any(devices & {item["uuid"] for item in target.get("reservations", [])}
           for operation in JobStore(store).all() for target in operation["targets"] if target["state"] not in TERMINAL):
        raise Failure("gpu_reserved", "A selected GPU is reserved by a managed SSH job.", 409)
    if any(devices & set(item.plan.job.limits.gpu_devices)
                           for item in Records(store).attempts() if item.state != "released"
                           and not (item.observed and item.observed.cleanup_confirmed)):
        raise Failure("gpu_reserved", "A selected GPU is reserved by contributor execution or an inference service.", 409)
