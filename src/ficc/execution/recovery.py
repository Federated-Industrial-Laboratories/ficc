# SPDX-License-Identifier: Apache-2.0
"""Recover a retained finite storage mount while the supervisor is stopped."""

import os
import time
from pathlib import Path

from .envelope import Envelope, context
from .ledger import Ledger
from .process import properties
from .storage import verify
from .supervisor import public


def recover(settings, asked, expected_generation):
    if os.geteuid() != 0:
        raise ValueError("Storage recovery requires the machine administrator.")
    current = properties(settings.service, ("LoadState", "ActiveState", "MainPID"))
    if current.get("ActiveState") not in {"inactive", "failed"} or current.get("MainPID") != "0":
        raise ValueError("Stop the installed executor supervisor before storage recovery.")
    ledger = Ledger(Path(settings.state), settings.installation_id)
    try:
        value = ledger.fenced(asked.attempt_id, asked.generation, asked.plan_digest)
        slot = next((item for item in settings.slots if item.id == value["slot"]), None)
        if slot is None:
            raise ValueError("The retained attempt has no installed storage slot.")
        before = value["binding"]
        if before["generation"] != expected_generation or slot.generation <= expected_generation:
            raise ValueError("Recovery requires the exact old and a strictly increased installed slot generation.")
        Envelope().stop(context(settings, slot, value))
        binding = verify(slot, idle=True)
        retained = ("slot_id", "filesystem_uuid", "storage_bytes", "storage_inodes", "uid", "gid", "inode")
        if any(binding[key] != before[key] for key in retained):
            raise ValueError("Recovery cannot substitute the reserved filesystem or workload account.")
        return public(ledger.recover_storage(asked, before, binding, time.time()))
    finally:
        ledger.close()
