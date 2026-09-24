# SPDX-License-Identifier: Apache-2.0
"""Run abrupt archive publication loss in a separate process with retained fixture state."""

import asyncio
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest
from ficc_node import history as node_history
from ficc_node import history_files, job_state
from test_history import acknowledge, controller
from test_history_node import node_state, request

from ficc import history, history_state
from ficc.errors import Failure
from ficc.service import Service
from ficc.settings import Settings


async def controller_run(folder, expected):
    result = await history.run(folder / "state", folder / "archive", True)
    with sqlite3.connect(folder / "archive/controller/state.sqlite3") as db:
        for table, rows in expected["rows"].items():
            assert [list(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")] == rows
    assert not any(bytes.fromhex(marker) in path.read_bytes()
                   for path in (folder / "archive").rglob("*") if path.is_file() for marker in expected["markers"])
    for name, value in expected["cli"].items():
        assert json.loads((folder / "archive/cli" / name).read_bytes()) == value
        assert not (folder / "state/cli-requests" / name).exists()
    service = Service(Settings(state_dir=folder / "state", control=False))
    try:
        for table in ("operations", "terminals", "file_operations", "transfers", "credentials"):
            assert service.store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        assert service.store.get_setting("file_reference_key", None) == expected["old"]["file_reference_key"]
        for credential in expected["credentials"]:
            with pytest.raises(Failure):
                service.auth.resolve(credential)
    finally:
        service.close()
    return result


def execute(action, kind, boundary, count, folder):
    with pytest.MonkeyPatch.context() as patch:
        if action == "crash":
            if kind == "node":
                body, _, original = node_state(folder / "home", patch, count)
                expected = {"original": {name: value.hex() for name, value in original.items()}}
            else:
                state, old, credentials, markers = controller(folder, count)
                cli = {}
                (state / "cli-requests").mkdir(mode=0o700)
                with sqlite3.connect(state / "state.sqlite3") as db:
                    for index in range(count):
                        key, secret = f"crash-cli-key-{index:05d}", f"crash-cli-credential-{index:05d}"
                        name = hashlib.sha256(key.encode()).hexdigest() + ".json"
                        value = {"key": key, "digest": f"digest-{index}", "grant": {"id": "fixture", "credential": secret}, "operation_id": f"job-{index}"}
                        job_state.write(state / "cli-requests" / name, value)
                        markers.append(secret.encode())
                        cli[name] = {"key": key, "digest": f"digest-{index}", "actor": "fixture", "operation_id": f"job-{index}"}
                        db.execute("UPDATE operations SET key=? WHERE id=?", (key, f"job-{index}"))
                    db.commit()
                    rows = {table: [list(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                            for table in ("operations", "terminals", "file_operations", "transfers", "nodes", "file_roots", "settings")}
                expected = {"old": old, "credentials": credentials, "markers": [value.hex() for value in markers], "rows": rows, "cli": cli}
            (folder / "expected.json").write_text(json.dumps(expected))
        else:
            expected = json.loads((folder / "expected.json").read_bytes())
        if kind == "node":
            patch.setenv("HOME", str(folder / "home"))
            patch.setattr(node_history.history_scan.job_system, "properties", lambda unit: {"LoadState": "not-found", "Id": unit})
            patch.setattr(node_history.history_scan, "no_tmux", lambda _: None)
            body = request()
        else:
            patch.setattr(history, "archive_node", acknowledge)
        if action == "crash":
            if boundary == "cli-created":
                actual_open = os.open
                last_name = sorted(expected["cli"])[-1]
                def opened(path, flags, *args, **kwargs):
                    fd = actual_open(path, flags, *args, **kwargs)
                    if flags & os.O_CREAT and Path(os.readlink(f"/proc/self/fd/{fd}")).parent == folder / "archive/cli" and Path(path).name in {last_name, ".archive-write-" + last_name + ".tmp"}:
                        (folder / "crash.json").write_text(json.dumps({"target": last_name}))
                        os._exit(77)
                    return fd
                patch.setattr(os, "open", opened)
            actual = os.replace
            def replace(source, destination, *args, **kwargs):
                name = Path(destination).name
                fd = os.open(source, os.O_RDONLY, dir_fd=kwargs.get("src_dir_fd"))
                with os.fdopen(fd, "rb") as stream:
                    value = json.load(stream)
                matches = {"node-intent": name == "intent.json" and value.get("state") == "moving",
                           "node-manifest": name == "manifest.json",
                           "node-published": name == "intent.json" and value.get("state") == "published",
                           "node-owner": name == "controller.json",
                           "node-complete": name == "intent.json" and value.get("state") == "complete",
                           "controller-initial": name == history_state.PENDING and "backup_sha256" not in value,
                           "controller-bound": name == history_state.PENDING and "backup_sha256" in value and not value["acknowledgements"],
                           "controller-ack": name == history_state.PENDING and bool(value.get("acknowledgements")),
                           "controller-retirement": name == "retirement.json",
                           "controller-complete": name == "archive.json" and value.get("state") == "complete",
                           "controller-cli-published": kind == "controller" and name == sorted(expected["cli"])[-1]}
                if matches.get(kind + "-" + boundary, False):
                    (folder / "crash.json").write_text(json.dumps({"target": name, "value": value}))
                    os._exit(77)
                return actual(source, destination, *args, **kwargs)
            patch.setattr(os, "replace", replace)
        if kind == "node":
            result = node_history.dispatch(body)
            archive = Path(result["path"])
            assert set(json.loads((archive / "manifest.json").read_bytes())["members"]) == set(expected["original"])
            for name, raw in expected["original"].items():
                assert (archive / name).read_bytes() == bytes.fromhex(raw)
            assert result["members"] == count * 6
            with pytest.raises(ValueError), job_state.locked(body["controller_id"]):
                pass
            with job_state.locked(body["next_controller_id"]):
                pass
            node_history.verify_archive(archive, job_state.read(archive / "manifest.json", history_files.MAX_MANIFEST))
        else:
            result = asyncio.run(controller_run(folder, expected))
        assert not list(folder.rglob(".archive-write-*.tmp"))
        print(json.dumps(result))
        if action == "crash":
            raise AssertionError("The process did not reach its requested publication boundary.")


if __name__ == "__main__":
    action, kind, boundary, count, folder = sys.argv[1:]
    execute(action, kind, boundary, int(count), Path(folder))
