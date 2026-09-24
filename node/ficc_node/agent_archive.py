# SPDX-License-Identifier: Apache-2.0
"""Retire only quiescent agent spools while preserving their admission records."""

import hashlib
import os

from . import agent_spool as spool
from . import terminals

MAX_ARCHIVES = 8192


def archived(controller, agent):
    parent = spool.root(controller)
    archive = parent / ".archives"
    if not archive.exists():
        return None
    spool.private(archive)
    target = archive / spool.identity(agent)
    if target.exists() or target.is_symlink():
        spool.private(target)
        return target
    return None


def describe(folder, controller, agent):
    spool.inventory(folder)
    spec = spool.read(folder / "spec.json")
    if spec["controller_id"] != controller or spec["agent_id"] != agent:
        raise ValueError("The archived agent identity changed.")
    digest = hashlib.sha256()
    members = 0
    for path in sorted(folder.iterdir()):
        if path.name == "lock" or path.name.startswith(".pending-"):
            continue
        fd = spool.checked_fd(path)
        try:
            raw = os.read(fd, spool.MAX_FILE + 1)
        finally:
            os.close(fd)
        digest.update(path.name.encode() + b"\0" + hashlib.sha256(raw).digest())
        members += 1
    return {"state": "archived", "agent_id": agent, "members": members,
            "sha256": digest.hexdigest(), "archive": str(folder)}


def retire(controller, agent):
    prior = archived(controller, agent)
    if prior is not None:
        spool.sync(prior.parent)
        spool.sync(prior.parent.parent)
        return describe(prior, controller, agent)
    with spool.locked(controller, agent) as folder:
        spec = spool.read(folder / "spec.json")
        runtime = spool.read(folder / "runtime.json")
        if runtime["state"] not in {"stopped", "exited"} or terminals.call(spec["terminal_controller"], "has-session", "-t", "=" + spec["terminal_id"]) == 0:
            raise ValueError("An active or uncertain agent spool cannot be archived.")
        if list(folder.glob("outbox-*.json")):
            raise ValueError("Unacknowledged agent outbox messages must be retained.")
        for path in folder.glob("receipt-*.json"):
            if spool.read(path)["state"] not in {"session-included", "tool-read", "failed", "cancelled"}:
                raise ValueError("Unresolved agent delivery receipts must be retained.")
        for path in folder.glob("inbox-*.json"):
            identity = path.name[6:-5]
            if not (folder / ("receipt-" + identity + ".json")).exists():
                raise ValueError("An unacknowledged inbox item must be retained.")
        archive = spool.private(folder.parent / ".archives")
        if len(list(archive.iterdir())) >= MAX_ARCHIVES:
            raise ValueError("The retained node agent archive limit was reached.")
        target = archive / agent
        if target.exists() or target.is_symlink():
            raise ValueError("The archive destination already exists.")
        spool.sync(archive)
        spool.sync(folder.parent)
        from .file_access import rename
        source_fd = os.open(folder.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        target_fd = os.open(archive, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            rename(source_fd, agent.encode(), target_fd, agent.encode())
        finally:
            os.close(source_fd)
            os.close(target_fd)
        spool.sync(archive)
        spool.sync(archive.parent)
        return describe(target, controller, agent)
