# SPDX-License-Identifier: Apache-2.0
"""Exclude credential-bearing CLI receipts only after closed-operation reconciliation."""

import hashlib
import os
import re

from . import backup_io as files


def reconciled(root, database, decode):
    try:
        folder = os.open("cli-requests", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    except FileNotFoundError:
        return
    try:
        files.checked(os.fstat(folder), directory=True)
        names = os.listdir(folder)
        if len(names) > 1025:
            raise ValueError("The CLI receipt count exceeds its limit.")
        for name in names:
            if name == "requests.lock":
                continue
            if not re.fullmatch(r"[a-f0-9]{64}\.json", name):
                raise ValueError("The CLI receipt directory contains an unsupported file.")
            value = decode(files.read(root, "cli-requests/" + name, 65536))
            if not isinstance(value, dict) or not isinstance(value.get("grant"), dict):
                raise ValueError("A saved CLI submission is invalid.")
            key, actor = value.get("key"), value["grant"].get("id")
            if (not isinstance(key, str) or not 16 <= len(key) <= 128
                    or hashlib.sha256(key.encode()).hexdigest() + ".json" != name
                    or not isinstance(actor, str) or not isinstance(value.get("digest"), str)):
                raise ValueError("A saved CLI submission identity is invalid.")
            row = database.execute("SELECT id,digest FROM operations WHERE actor=? AND key=?", (actor, key)).fetchone()
            if (row is None or row[1] != value["digest"]
                    or value.get("operation_id") not in (None, row[0])):
                raise ValueError("Reconcile every saved CLI submission before backup; its operation must be retained and closed.")
    finally:
        os.close(folder)
