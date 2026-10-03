# SPDX-License-Identifier: Apache-2.0
"""Bind storage reservations to finite mounted filesystems and separate workload accounts."""

import grp
import os
import pwd
import stat
from pathlib import Path

from .files import directory
from .process import command


def mount_rows(path=Path("/proc/self/mountinfo")):
    rows = []
    for line in path.read_text().splitlines():
        parts = line.split()
        separator = parts.index("-")
        if len(parts) != separator + 4 or separator < 6:
            raise ValueError("The kernel mount table is invalid.")
        rows.append({"id": parts[0], "device": parts[2], "root": parts[3], "target": parts[4],
                     "options": parts[5].split(","), "fstype": parts[separator + 1],
                     "source": parts[separator + 2], "super_options": parts[separator + 3]})
    return rows


def processes(uid):
    found = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            if path.stat().st_uid == uid:
                found.append(int(path.name))
        except FileNotFoundError:
            pass
    return found


def verify(slot, previous=None, *, idle=False):
    mount = Path(slot.mount)
    info = directory(mount)
    user, group = pwd.getpwnam(slot.account), grp.getgrnam(slot.account)
    if (user.pw_uid, user.pw_gid, group.gr_gid) != (slot.uid, slot.gid, slot.gid):
        raise ValueError("A workload account no longer matches the configured slot.")
    if user.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"} or grp.getgrgid(slot.gid).gr_mem:
        raise ValueError("A workload account permits login or a shared primary group.")
    if any(slot.account in item.gr_mem for item in grp.getgrall()):
        raise ValueError("A workload account has an unapproved supplementary group.")
    rows = [row for row in mount_rows() if row["target"] == slot.mount]
    if len(rows) != 1 or rows[0]["root"] != "/" or "rw" not in rows[0]["options"]:
        raise ValueError("The configured slot is not one independent writable filesystem mount.")
    row = rows[0]
    if row["fstype"] != "ext4" or not {"nosuid", "nodev"} <= set(row["options"]):
        raise ValueError("The storage filesystem or restricted mount flags are not qualified.")
    device = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
    if row["device"] != device or info.st_dev == mount.parent.stat().st_dev:
        raise ValueError("The storage mount does not have an independent device identity.")
    block = Path("/dev/block") / device
    uuid = command(["/usr/sbin/blkid", "-s", "UUID", "-o", "value", str(block)])["stdout"].strip()
    if uuid != slot.filesystem_uuid:
        raise ValueError("The storage filesystem UUID differs from the installed slot.")
    space = os.statvfs(mount)
    maximum, inodes = space.f_blocks * space.f_frsize, space.f_files
    if not 0 < maximum <= slot.storage_bytes or not 0 < inodes <= slot.storage_inodes:
        raise ValueError("The mounted storage capacity exceeds the installed slot class.")
    binding = {"slot_id": slot.id, "generation": slot.generation, "mount_id": row["id"],
               "device": info.st_dev, "inode": info.st_ino, "filesystem_uuid": uuid,
               "storage_bytes": maximum, "storage_inodes": inodes, "uid": slot.uid, "gid": slot.gid}
    if previous is not None and binding != previous:
        raise ValueError("The reserved storage or account identity changed.")
    if idle and processes(slot.uid):
        raise ValueError("A workload account still has processes. Quarantine its storage slot.")
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("The storage mount is not a directory.")
    return binding
