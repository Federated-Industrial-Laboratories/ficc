# SPDX-License-Identifier: Apache-2.0
"""Retire one closed controller epoch with resumable private node archives."""

import fcntl
import os
import re
import stat
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from . import file_state, history_scan, history_write, job_state, terminals
from . import history_files as files
from .job_spec import ID

FIELDS = {"version", "action", "archive_id", "controller_id", "terminal_controller", "next_controller_id", "next_terminal_controller"}


def validate(request):
    if set(request) != FIELDS or request["version"] != "3" or request["action"] != "history.archive":
        raise ValueError("Invalid history archive request.")
    for name in FIELDS - {"version", "action"}:
        if not isinstance(request[name], str) or not ID.fullmatch(request[name]):
            raise ValueError("Invalid history archive identity.")
    if request["next_controller_id"] == request["controller_id"] or request["next_terminal_controller"] == request["terminal_controller"]:
        raise ValueError("History archival requires fresh controller identities.")


@contextmanager
def lock(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("Archive locks must be private regular files.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def save(path, value):
    history_write.write(path, value, files.MAX_MANIFEST)


def result(folder, manifest):
    detail = files.fingerprint(folder / "manifest.json", files.MAX_MANIFEST)
    return {"archive_id": manifest["request"]["archive_id"], "state": "complete", "path": str(folder),
            "manifest_sha256": detail["sha256"], "members": len(manifest["members"]),
            "bytes": sum(value["size"] for value in manifest["members"].values()),
            "controller_id": manifest["request"]["controller_id"],
            "next_controller_id": manifest["request"]["next_controller_id"]}


def validate_members(value):
    members = value.get("members")
    if not isinstance(members, dict) or len(members) > files.MAX_MEMBERS:
        raise ValueError("The retained history manifest is invalid.")
    total = 0
    for name, detail in members.items():
        maximum = files.maximum(name)
        if (not isinstance(detail, dict) or set(detail) != {"size", "sha256"}
                or type(detail["size"]) is not int or not 0 <= detail["size"] <= maximum
                or not isinstance(detail["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", detail["sha256"])):
            raise ValueError("The retained history member is invalid.")
        total += detail["size"]
    if total > files.MAX_BYTES:
        raise ValueError("The retained history exceeds its size limit.")
    return members


def verify_archive(folder, value):
    members = validate_members(value)
    allowed = {"intent.json", "manifest.json"} | {name.split("/")[0] for name in members}
    if not set(files.entries(folder, 5)).issubset(allowed):
        raise ValueError("The retained archive contains unexpected files.")
    for kind in ("jobs", "files", "terminals"):
        expected_names = {group.split("/", 1)[1] for group in files.groups(members) if group.startswith(kind + "/")}
        if expected_names and set(files.entries(folder / kind, files.MAX_MEMBERS)) != expected_names:
            raise ValueError("An archived namespace contains missing or unexpected records.")
    deadline = time.monotonic() + 300
    for group in files.groups(members):
        files.verify_group(folder / group, group, members, deadline)


def dispatch(request):
    validate(request)
    jobs = job_state.root()
    history = job_state.directory(jobs.parent / "history")
    folder = history / request["archive_id"]
    with lock(jobs / "lock"):
        owner_path = jobs / "controller.json"
        history_write.recover(owner_path, 131072)
        if folder.exists() or folder.is_symlink():
            job_state.directory(folder)
            for name in ("intent.json", "manifest.json"):
                history_write.recover(folder / name, files.MAX_MANIFEST)
            previous = job_state.read(folder / "intent.json", files.MAX_MANIFEST) if (folder / "intent.json").exists() else None
            if previous and previous.get("request") != request:
                raise ValueError("This archive identity belongs to another request.")
            if previous and previous.get("state") == "complete":
                manifest = job_state.read(folder / "manifest.json", files.MAX_MANIFEST)
                if manifest.get("request") != request or manifest.get("members") != previous.get("members"):
                    raise ValueError("The completed history manifest changed.")
                verify_archive(folder, manifest)
                return result(folder, manifest)
        else:
            previous = None
        owner = job_state.read(owner_path) if owner_path.exists() else None
        expected = {"id": request["controller_id"]}
        resumed_owner = previous is not None and owner == {"id": request["next_controller_id"]}
        if owner not in (None, expected) and not resumed_owner:
            raise ValueError("The job namespace belongs to another controller.")
        bases = {"jobs": jobs, "files": job_state.directory(file_state.state_root() / request["controller_id"]),
                 "terminals": terminals.base(request["terminal_controller"])}
        with ExitStack() as locks:
            locks.enter_context(lock(bases["files"] / "namespace.lock"))
            locks.enter_context(lock(bases["terminals"] / "lock"))
            if previous is None:
                members = history_scan.scan(bases, request)
                job_state.directory(folder)
                if files.entries(folder, 1):
                    raise ValueError("The archive directory contains unrecognised state.")
                previous = {"format": 1, "state": "moving", "request": request, "members": members}
                save(folder / "intent.json", previous)
                job_state.sync_directory(history)
            elif previous.get("state") not in {"moving", "published"} or previous.get("format") != 1:
                raise ValueError("The node archive intent is invalid.")
            validate_members(previous)
            history_write.persist(folder, Path.home())
            remaining = history_scan.scan(bases, request)
            if any(previous["members"].get(name) != detail for name, detail in remaining.items()):
                raise ValueError("New or changed work appeared after the archive intent.")
            files.move_groups(bases, folder, previous["members"])
            manifest = {"format": 1, "request": request, "members": previous["members"]}
            if (folder / "manifest.json").exists():
                if job_state.read(folder / "manifest.json", files.MAX_MANIFEST) != manifest:
                    raise ValueError("The node archive manifest changed.")
            else:
                save(folder / "manifest.json", manifest)
            verify_archive(folder, manifest)
            previous["state"] = "published"
            save(folder / "intent.json", previous)
            history_write.write(owner_path, {"id": request["next_controller_id"]}, 131072)
            previous["state"] = "complete"
            save(folder / "intent.json", previous)
            return result(folder, manifest)
