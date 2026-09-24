# SPDX-License-Identifier: Apache-2.0
"""Retain bounded private CLI receipts across uncertain submission responses."""

import fcntl
import hashlib
import json
import os
import re
import secrets
import sys
import time
from contextlib import suppress

import httpx

from .launcher_config import read_private, write_file
from .settings import private_directory


def submit_saved(args, request: dict) -> dict:
    from .cli import local_request
    from .job_cli import reply

    key = args.idempotency_key or secrets.token_hex(24)
    if not re.fullmatch(r"[\x21-\x7e]{16,128}", key):
        raise ValueError("The idempotency key must contain 16 to 128 printable non-space characters.")
    print(json.dumps({"idempotency_key": key}), file=sys.stderr)
    digest = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    directory = args.state_dir / "cli-requests"
    private_directory(directory)
    path = directory / (hashlib.sha256(key.encode()).hexdigest() + ".json")
    lock = os.open(directory / "requests.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another CLI submission is busy. Retry with the same idempotency key.") from None
        if path.exists() or path.is_symlink():
            saved = json.loads(read_private(path))
            if saved["key"] != key or saved["digest"] != digest:
                raise ValueError("This idempotency key already belongs to a different request.")
        else:
            if sum(1 for _ in directory.iterdir()) >= 1025:
                raise ValueError("The CLI receipt limit is full. Archive completed receipts before submitting more work.")
            grant = local_request(args.state_dir, {"action": "job-credential"})
            saved = {"key": key, "digest": digest, "grant": grant, "operation_id": None}
            write_file(path, json.dumps(saved))
        if saved["operation_id"]:
            grant = local_request(args.state_dir, {"action": "ephemeral"})
        else:
            grant = saved["grant"]
            if time.time() >= grant["expires_at"]:
                raise ValueError("The saved submission credential expired. Inspect job-list before any new submission.")
        revoke = bool(saved["operation_id"])
        try:
            with httpx.Client(base_url=grant["origin"], headers={"Authorization": "Bearer " + grant["credential"]},
                              timeout=90, trust_env=False) as client:
                if saved["operation_id"]:
                    operation = reply(client.get("/api/v1/operations/" + saved["operation_id"]))
                else:
                    if not saved.get("preview_id"):
                        preview = reply(client.post("/api/v1/operation-previews", json=request))
                        saved["preview_id"] = preview["preview_id"]
                        write_file(path, json.dumps(saved))
                    operation = reply(client.post("/api/v1/operations", json={"preview_id": saved["preview_id"]},
                                                  headers={"Idempotency-Key": key}))
                    saved["operation_id"] = operation["id"]
                    write_file(path, json.dumps(saved))
                    deadline = time.monotonic() + 10
                    while True:
                        revoke = all(target["state"] not in {"queued", "dispatching"}
                                     for target in operation["targets"])
                        if revoke or time.monotonic() >= deadline:
                            break
                        time.sleep(0.25)
                        operation = reply(client.get("/api/v1/operations/" + operation["id"]))
                return {"operation": operation, "idempotency_key": key, "submitted": True}
        finally:
            if revoke:
                with suppress(OSError, ValueError):
                    local_request(args.state_dir, {"action": "revoke", "id": grant["id"]})
                    if saved["grant"]["id"] == grant["id"] and saved["operation_id"]:
                        saved["grant"].pop("credential", None)
                        write_file(path, json.dumps(saved))
            else:
                print(json.dumps({"dispatch_credential_id": grant["id"], "expires_at": grant["expires_at"],
                                  "note": "Retry with the same key to recover this submission. Revoke its credential in Access to prevent queued launch."}),
                      file=sys.stderr)
    finally:
        os.close(lock)
