# SPDX-License-Identifier: Apache-2.0
"""Preview and resume explicit archival of a stopped controller execution epoch."""

import asyncio
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path

from ficc_node import history_write

from . import backup
from . import backup_io as files
from . import history_state as state
from .history_transport import archive as archive_node
from .settings import Settings, default_state_dir
from .ssh import SSH
from .state_lock import StateLock


def validate(intent, output, ssh_config):
    if not isinstance(intent, dict):
        raise ValueError("The pending history intent is invalid.")
    for key in ("archive_id", "controller_id", "terminal_controller", "next_controller_id", "next_terminal_controller"):
        if not isinstance(intent.get(key), str) or not re.fullmatch(files.HEX32, intent[key]):
            raise ValueError("The pending history identity is invalid.")
    nodes = intent.get("nodes")
    if (not isinstance(nodes, list) or len(nodes) > 64
            or any(not isinstance(node, dict) or not isinstance(node.get("id"), str)
                   or not 1 <= len(node["id"]) <= 128 for node in nodes)):
        raise ValueError("The pending history node list is invalid.")
    identities = {node["id"] for node in nodes}
    if (intent.get("format") != 1 or intent.get("output") != str(output)
            or intent.get("ssh_config") != (str(ssh_config) if ssh_config else None)
            or len(identities) != len(nodes) or not isinstance(intent.get("preview"), dict)
            or intent["controller_id"] == intent["next_controller_id"]
            or intent["terminal_controller"] == intent["next_terminal_controller"]
            or not isinstance(intent.get("acknowledgements"), dict)
            or not set(intent["acknowledgements"]).issubset(identities)):
        raise ValueError("Resume the pending archive with its original output and SSH configuration.")


def summary(intent, complete):
    return {"archive_id": intent["archive_id"], "archived": complete, "output": intent["output"],
            "preview": intent["preview"], "node_archives": intent["acknowledgements"],
            "note": "Archived node output remains on each node. Keep the old controller stopped and use fresh credentials and command keys."}


def local_output(output, intent):
    if output.exists() or output.is_symlink():
        for name, maximum in (("archive.json", state.MAX_INTENT), ("retirement.json", files.MAX_MANIFEST)):
            history_write.recover(output / name, maximum)
        saved = state.read(output / "archive.json")
        if saved.get("archive_id") != intent["archive_id"]:
            raise ValueError("The output directory belongs to another archive.")
    else:
        with files.staging(output) as (folder, _):
            files.write(folder, "archive.json", files.encode({"format": 1, "state": "pending", "archive_id": intent["archive_id"]}))


async def run(state_dir: Path, output: Path, confirm=False, ssh_config=None):
    state_dir, output = Path(os.path.abspath(state_dir)), Path(os.path.abspath(output))
    ssh_config = Path(os.path.abspath(ssh_config)) if ssh_config else None
    if output.is_relative_to(state_dir):
        raise ValueError("Store the history archive outside the controller state directory.")
    with files.directory(state_dir), StateLock(state_dir) as ownership:
        pending = state_dir / state.PENDING
        history_write.recover(pending, state.MAX_INTENT)
        if pending.exists() or pending.is_symlink():
            intent = state.read(pending)
            validate(intent, output, ssh_config)
            if not confirm:
                return {**summary(intent, False), "resume_required": True}
        else:
            if output.exists() or output.is_symlink():
                saved = state.read(output / "archive.json")
                if saved.get("state") == "complete" and isinstance(saved.get("intent"), dict):
                    validate(saved["intent"], output, ssh_config)
                    state.verify_backup(output / "controller", saved["intent"]["backup_sha256"])
                    return summary(saved["intent"], True)
                raise ValueError("The history output must be a new directory.")
            initial = state.inspect(state_dir)
            if not confirm:
                return {"preview": initial["preview"], "archived": False,
                        "note": "Stop all recorded work and pass --confirm to retire this controller epoch and revoke all credentials."}
            if any(not node.get("capabilities", {}).get("history_archive") for node in initial["nodes"]):
                raise ValueError("Upgrade and refresh every enrolled helper before history archival.")
            intent = {**initial, "format": 1, "archive_id": secrets.token_hex(16),
                      "next_controller_id": secrets.token_hex(16), "next_terminal_controller": secrets.token_hex(16),
                      "output": str(output), "ssh_config": str(ssh_config) if ssh_config else None,
                      "acknowledgements": {}}
            state.save(pending, intent)
        local_output(output, intent)
        copied = output / "controller"
        if not copied.exists():
            backup.export_locked(state_dir, copied, ownership, maintenance=True)
        manifest, signature = state.verify_backup(copied, intent.get("backup_sha256"))
        if manifest["controller_id"] != intent["controller_id"]:
            raise ValueError("The history backup belongs to another controller.")
        intent["backup_sha256"] = signature
        receipts, signature = state.local_receipts(state_dir, output, manifest)
        if intent.get("retirement_sha256", signature) != signature:
            raise ValueError("The local retirement manifest changed.")
        intent["retirement_sha256"] = signature
        state.save(pending, intent)
        if not state.committed(state_dir, intent):
            current = state.inspect(state_dir)
            if current["database_sha256"] != intent["database_sha256"]:
                raise ValueError("Controller state changed after archival began.")
            transport = SSH(Settings(state_dir=state_dir, ssh_config=ssh_config, control=False))
            try:
                for node in intent["nodes"]:
                    if node["id"] not in intent["acknowledgements"]:
                        intent["acknowledgements"][node["id"]] = await archive_node(transport, node, intent)
                        state.save(pending, intent)
            finally:
                await transport.close()
            state.commit(state_dir, intent)
        if len(intent["acknowledgements"]) != len(intent["nodes"]):
            raise ValueError("The controller commit has incomplete node acknowledgements.")
        state.retire(state_dir, output, receipts)
        state.save(output / "archive.json", {"format": 1, "state": "complete", "archive_id": intent["archive_id"], "intent": intent})
        pending.unlink()
        with files.directory(state_dir) as fd:
            os.fsync(fd)
        return summary(intent, True)


def add_commands(commands):
    parser = commands.add_parser("archive-history", help="Preview or archive all closed controller and node history.")
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--confirm", action="store_true",
                        help="Retire the displayed execution epoch and revoke all credentials.")


def execute(args):
    try:
        result = asyncio.run(run(args.state_dir, args.output, args.confirm, args.ssh_config))
    except sqlite3.Error:
        raise ValueError("History archival could not verify or save controller state. Resume the same command after storage recovery.") from None
    print(json.dumps(result, indent=2))
