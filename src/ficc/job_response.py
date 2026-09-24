# SPDX-License-Identifier: Apache-2.0
"""Reject malformed managed-job responses before they enter controller state."""

import base64
import math

from ficc_node.job_spec import ID, TERMINAL


def integer(value):
    return type(value) is int and 0 <= value <= 2**63 - 1


def validate(action, value):
    if not isinstance(value, dict):
        raise ValueError("Invalid helper response.")
    if action == "job.capabilities":
        if type(value.get("jobs")) is not bool or type(value.get("logout_persistent")) is not bool:
            raise ValueError("Invalid capability response.")
        if "job_error" in value and (not isinstance(value["job_error"], str) or len(value["job_error"]) > 256):
            raise ValueError("Invalid capability error.")
    elif action == "job.logs":
        if set(value) != {"data_base64", "next_offset", "total_bytes", "dropped_bytes", "complete"}:
            raise ValueError("Invalid log response.")
        data = value["data_base64"]
        if not isinstance(data, str) or len(data) > 87384 or len(base64.b64decode(data, validate=True)) > 65536:
            raise ValueError("Invalid log data.")
        if not integer(value["next_offset"]) or not integer(value["total_bytes"]) or type(value["complete"]) is not bool:
            raise ValueError("Invalid log position.")
        if value["dropped_bytes"] is not None and not integer(value["dropped_bytes"]):
            raise ValueError("Invalid dropped-byte count.")
    else:
        if not isinstance(value.get("job_id"), str) or not ID.fullmatch(value["job_id"]):
            raise ValueError("Invalid job identity.")
        if value.get("state") not in TERMINAL | {"running", "unknown", "cancel_requested"}:
            raise ValueError("Invalid job state.")
        if value.get("error") is not None and (not isinstance(value["error"], str) or len(value["error"]) > 256):
            raise ValueError("Invalid job error.")
        result = value.get("result")
        if result is not None:
            if not isinstance(result, dict) or set(result) != {"exit_code", "signal", "reason", "stdout_bytes", "stderr_bytes", "dropped_bytes", "finished_at"}:
                raise ValueError("Invalid job result.")
            for key in ("exit_code", "signal", "stdout_bytes", "stderr_bytes", "dropped_bytes"):
                if result[key] is not None and not integer(result[key]):
                    raise ValueError("Invalid job result count.")
            if not isinstance(result["reason"], str) or len(result["reason"]) > 256:
                raise ValueError("Invalid job result reason.")
            finished = result["finished_at"]
            if finished is not None and (type(finished) not in (int, float) or not 0 <= finished <= 2**63 - 1 or not math.isfinite(finished)):
                raise ValueError("Invalid job completion time.")
        if value["state"] in TERMINAL and result is None:
            raise ValueError("A terminal job requires an authoritative result.")
        limits = value.get("effective_limits")
        if limits is not None:
            if not isinstance(limits, dict) or len(limits) > 6:
                raise ValueError("Invalid effective limits.")
            for number in limits.values():
                if type(number) not in (int, float) or not 0 <= number <= 2**63 - 1 or not math.isfinite(number):
                    raise ValueError("Invalid effective limit value.")
        if "session_lifetime" in value and type(value["session_lifetime"]) is not bool:
            raise ValueError("Invalid session lifetime.")
    return value
