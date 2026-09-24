# SPDX-License-Identifier: Apache-2.0
"""Validate bounded job arguments on both sides of the SSH connection."""

import json
import re

ID = re.compile(r"[0-9a-f]{32}\Z")
ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
LIMITS = {
    "cpu_percent": (1, 6553600),
    "memory_high_bytes": (16777216, 2**60),
    "memory_max_bytes": (33554432, 2**60),
    "memory_swap_max_bytes": (0, 2**60),
    "tasks_max": (4, 65536),
    "runtime_seconds": (1, 86400),
}
TERMINAL = {"succeeded", "failed", "cancelled", "interrupted"}
LOG_CAP = 64 * 1024 * 1024
TOTAL_LOG_CAP = 2 * 1024 * 1024 * 1024
RECEIPT_CAP = 256


def text(value, maximum, empty=False):
    if not isinstance(value, str) or "\0" in value or len(value.encode()) > maximum:
        raise ValueError("Invalid text field.")
    if not empty and not value:
        raise ValueError("Empty text field.")


def validate_job(job):
    if not isinstance(job, dict) or set(job) != {
        "label", "argv", "cwd", "env", "limits", "allow_session_lifetime", "gpu_reservations"
    }:
        raise ValueError("Invalid job fields.")
    text(job["label"], 80)
    argv = job["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise ValueError("Invalid argument count.")
    for arg in argv:
        text(arg, 4096, empty=True)
    if not argv[0] or sum(len(arg.encode()) for arg in argv) > 32768:
        raise ValueError("Invalid argument size.")
    text(job["cwd"], 4096, empty=True)
    if job["cwd"] and not job["cwd"].startswith("/"):
        raise ValueError("Working directory must be absolute.")
    env = job["env"]
    if not isinstance(env, dict) or len(env) > 64:
        raise ValueError("Invalid environment count.")
    for name, value in env.items():
        if not isinstance(name, str) or not ENV.fullmatch(name) or name == "CUDA_VISIBLE_DEVICES":
            raise ValueError("Invalid or reserved environment name.")
        text(value, 4096, empty=True)
    if len(json.dumps(env).encode()) > 16384:
        raise ValueError("Environment exceeds the limit.")
    limits = job["limits"]
    if not isinstance(limits, dict) or set(limits) != set(LIMITS):
        raise ValueError("All resource limits are required.")
    for key, (low, high) in LIMITS.items():
        if type(limits[key]) is not int or not low <= limits[key] <= high:
            raise ValueError("Invalid resource limit.")
    if limits["memory_high_bytes"] > limits["memory_max_bytes"]:
        raise ValueError("Memory high must not exceed memory max.")
    if type(job["allow_session_lifetime"]) is not bool:
        raise ValueError("Invalid session lifetime choice.")
    reservations = job["gpu_reservations"]
    if not isinstance(reservations, dict) or len(reservations) > 64:
        raise ValueError("Invalid GPU reservations.")
    for node, devices in reservations.items():
        text(node, 80)
        if not isinstance(devices, list) or len(devices) > 64:
            raise ValueError("Invalid GPU count.")
        seen = set()
        for device in devices:
            if not isinstance(device, dict) or set(device) != {"uuid", "memory_bytes"}:
                raise ValueError("Invalid GPU reservation.")
            uuid = device["uuid"]
            if not isinstance(uuid, str) or not re.fullmatch(r"GPU-[A-Za-z0-9-]{1,96}", uuid) or uuid in seen:
                raise ValueError("Invalid or repeated GPU UUID.")
            seen.add(uuid)
            if type(device["memory_bytes"]) is not int or not 1 <= device["memory_bytes"] <= 2**60:
                raise ValueError("Invalid GPU memory reservation.")
    if len(json.dumps(job, allow_nan=False).encode()) > 65536:
        raise ValueError("The serialized job exceeds 64 KiB.")
    return job
