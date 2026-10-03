# SPDX-License-Identifier: Apache-2.0
"""Verify standard character-device mounts and restricted null masks."""
import os
import stat
from pathlib import Path

DEVICES = {"null": (1, 3), "zero": (1, 5), "full": (1, 7), "tty": (5, 0),
           "random": (1, 8), "urandom": (1, 9)}
MASKS = {"/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/interrupts"}


def parse(row):
    parts = row.split()
    separator = parts.index("-")
    if len(parts) != separator + 4 or separator < 6:
        raise ValueError("Unexpected mountinfo structure.")
    return {"id": parts[0], "device": parts[2], "root": parts[3], "target": parts[4],
            "options": parts[5].split(","), "fstype": parts[separator + 1],
            "source": parts[separator + 2], "super_options": parts[separator + 3]}


def metadata(info):
    return {"mode": info.st_mode, "device": [os.major(info.st_dev), os.minor(info.st_dev)],
            "rdev": [os.major(info.st_rdev), os.minor(info.st_rdev)], "inode": info.st_ino}


def host_identity():
    rows = Path("/proc/self/mountinfo").read_text().splitlines()
    selected = [parse(row) for row in rows if row.split()[4] == "/dev"]
    if len(selected) != 1:
        raise ValueError("The host /dev mount is not unique.")
    return {"mount": selected[0], "directory": metadata(os.lstat("/dev"))}


def target(row):
    mounted = parse(row)
    destination = mounted["target"]
    if destination in MASKS:
        name, required = "null", {"ro", "nosuid"}
        allowed = required | {"noexec"}
    elif destination.startswith("/dev/") and destination[5:] in DEVICES:
        name, required = destination[5:], {"rw", "nosuid", "noexec"}
        allowed = required
    else:
        raise ValueError("The target is not an explicitly allowed standard node or null mask.")
    if mounted["fstype"] != "devtmpfs" or mounted["root"] != "/" + name:
        raise ValueError("The filesystem type or exact bind root differs.")
    flags = set(mounted["options"])
    if not required <= flags <= allowed:
        raise ValueError("The bind does not have the required restricted mount flags.")
    return name, mounted


def validate(row, host, host_node, payload_node, mount_count):
    name, mounted = target(row)
    host_mount, directory = host["mount"], host["directory"]
    if mount_count != 1 or host_mount["target"] != "/dev" or host_mount["root"] != "/" or host_mount["fstype"] != "devtmpfs":
        raise ValueError("The exact host device mount or payload target is not unique.")
    if not stat.S_ISDIR(directory["mode"]):
        raise ValueError("The host device mount is not a directory.")
    device = ":".join(map(str, directory["device"]))
    if mounted["device"] != device or host_mount["device"] != device:
        raise ValueError("The bind is not on the actual host devtmpfs superblock.")
    expected = list(DEVICES[name])
    for label, node in (("host", host_node), ("payload", payload_node)):
        if not stat.S_ISCHR(node["mode"]) or node["rdev"] != expected or node["device"] != directory["device"]:
            raise ValueError(label + " node has the wrong type, filesystem or device number.")
    if host_node["inode"] <= 0 or payload_node["inode"] != host_node["inode"]:
        raise ValueError("The payload does not bind the exact standard host-device inode.")
    return {"verified_target": mounted["target"], "mount": mounted, "host_mount": host_mount,
            "host_directory": directory, "host_node": host_node, "payload_node": payload_node}


def verify(row, pid, mounts):
    name, mounted = target(row)
    host = host_identity()
    host_node = metadata(os.lstat("/dev/" + name))
    payload_node = metadata(os.lstat(Path("/proc") / str(pid) / "root" / mounted["target"].lstrip("/")))
    count = sum(item.split()[4] == mounted["target"] for item in mounts)
    return validate(row, host, host_node, payload_node, count)
