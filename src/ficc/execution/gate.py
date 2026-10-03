# SPDX-License-Identifier: Apache-2.0
"""Verify the live payload boundary before the trusted executable can release a job."""

import os
import re
import stat
from pathlib import Path

from . import device_mounts
from .files import atomic
from .storage import mount_rows


def require(value, message):
    if not value:
        raise ValueError(message)


def core_limit(value):
    require(re.search(r"^Max core file size\s+0\s+0\s+bytes[ \t]*$", value, flags=re.MULTILINE) is not None,
            "The payload can write a core dump outside its reserved storage.")


def bind(row, expected, root):
    source = Path(expected["source"]).lstat()
    target = (root / row["target"].lstrip("/")).lstat()
    saved = expected["identity"]
    require(all((item.st_dev, item.st_ino, item.st_mode) ==
                (saved["device"], saved["inode"], saved["mode"]) for item in (source, target)),
            "A payload mount has another source identity.")
    flags = set(row["options"])
    require({"nosuid"} <= flags, "A payload bind permits set-user-ID files.")
    if expected["read_only"]:
        require("ro" in flags and "rw" not in flags, "An immutable payload bind is writable.")
    elif not stat.S_ISCHR(saved["mode"]):
        require("rw" in flags and "nodev" in flags, "A work bind has different access flags.")
    require(row["device"] == f"{os.major(saved['device'])}:{os.minor(saved['device'])}",
            "A payload bind has another filesystem device.")
    if stat.S_ISCHR(saved["mode"]):
        require(all(item.st_rdev == saved["rdev"] for item in (source, target)),
                "A selected character device has another major or minor number.")
        host = device_mounts.host_identity()
        require(row["fstype"] == "devtmpfs" and row["root"] == "/" + Path(expected["source"]).name
                and row["device"] == host["mount"]["device"] and flags == {"rw", "nosuid", "noexec"},
                "A selected device is not the exact restricted host device mount.")
    elif stat.S_ISREG(saved["mode"]):
        require(all(item.st_size == saved["bytes"] and item.st_mtime_ns == saved["mtime_ns"]
                    for item in (source, target)), "An immutable payload file changed.")
        require("nodev" in flags, "A payload file bind permits devices.")
    else:
        require(stat.S_ISDIR(saved["mode"]) and "nodev" in flags,
                "A payload directory bind has an unsupported type or device flag.")


def filesystem(ctx, prepared, pid, rows, raw):
    root = Path("/proc") / str(pid) / "root"
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["target"]] = counts.get(row["target"], 0) + 1
    require(counts.get("/") == 1, "The payload root mount is not unique.")
    main = next(row for row in rows if row["target"] == "/")
    require(main["fstype"] in {"overlay", "fuse-overlayfs"} and "ro" in main["options"],
            "The payload root is not a read-only layered filesystem.")
    runtime = str(Path(ctx["directory"]) / "runtime")
    options = dict(item.split("=", 1) for item in main["super_options"].split(",") if "=" in item)
    for name in ("lowerdir", "upperdir", "workdir"):
        require(name in options and all(path.startswith(runtime + "/storage/") and "/../" not in path
                                        for path in options[name].split(":")),
                "The payload root storage is outside the reserved filesystem.")
    mounts = {item["target"]: item for item in prepared["mounts"]}
    require(len(mounts) == len(prepared["mounts"]), "Payload mount targets are not unique.")
    require(all(counts.get(target) == 1 for target in mounts), "An approved payload bind is absent or covered.")
    slot_device = f"{os.major(ctx['binding']['device'])}:{os.minor(ctx['binding']['device'])}"
    slot_prefix = "/" + str(Path(ctx["directory"]).relative_to(ctx["slot"]["mount"])) + "/runtime/"
    for row in rows:
        target, kind, flags = row["target"], row["fstype"], set(row["options"])
        if target in mounts:
            bind(row, mounts[target], root)
        elif target == "/":
            continue
        elif target in prepared["generated_targets"]:
            require(row["device"] == slot_device and row["root"].startswith(slot_prefix)
                    and {"ro", "nosuid", "nodev"} <= flags,
                    "A generated runtime file is outside the reserved filesystem or is writable.")
        elif kind == "proc":
            require(target == "/proc" or target.startswith("/proc/") and "ro" in flags,
                    "A process filesystem mount has unexpected access.")
        elif kind in {"sysfs", "cgroup2", "tmpfs"}:
            require("ro" in flags and (target.startswith("/sys") or target.startswith("/proc/")
                                       or target in {"/dev", "/dev/shm"}),
                    "A kernel filesystem is writable or mounted at an unexpected target.")
        elif kind in {"devpts", "mqueue"}:
            require(target == {"devpts": "/dev/pts", "mqueue": "/dev/mqueue"}[kind]
                    and {"nosuid", "noexec"} <= flags, "A private device filesystem has unexpected access.")
        else:
            original = next(line for line in raw if line.split()[0] == row["id"])
            device_mounts.verify(original, pid, raw)


def inspect(ctx, prepared, pid):
    require(type(pid) is int and pid > 1, "The runtime did not identify a live payload.")
    path = Path("/proc") / str(pid)
    started = (path / "stat").read_text().rsplit(")", 1)[1].split()[19]
    status = (path / "status").read_text()
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    raw_mounts = (path / "mountinfo").read_text().splitlines()
    group = (path / "cgroup").read_text().strip()
    limits = (path / "limits").read_text()
    descriptors = [os.readlink(item) for item in (path / "fd").iterdir()]
    observed = {"pid": pid, "start_time": started, "status": status, "mountinfo": raw_mounts,
                "cgroup": group, "descriptors": descriptors, "limits": limits}
    atomic(Path(ctx["directory"]) / "inspection.json", observed)
    require([int(value) for value in fields["Uid"].split()] == [ctx["slot"]["uid"]] * 4
            and [int(value) for value in fields["Gid"].split()] == [ctx["slot"]["gid"]] * 4,
            "The payload has an unexpected host account.")
    require(all(int(fields[name].strip(), 16) == 0 for name in ("CapEff", "CapPrm", "CapBnd"))
            and fields["NoNewPrivs"].strip() == "1" and fields["Seccomp"].strip() == "2",
            "The payload retains privileges or lacks its system-call filter.")
    core_limit(limits)
    require(group.startswith("0::" + ctx["cgroup"] + "/"), "The payload escaped its system-owned ancestor.")
    for name in ("mnt", "pid", "net", "user", "ipc", "uts", "cgroup"):
        require((path / "ns" / name).stat().st_ino != (Path("/proc/self/ns") / name).stat().st_ino,
                "The payload shares a host namespace.")
    for name, expected in (("uid_map", ctx["slot"]["uid"]), ("gid_map", ctx["slot"]["gid"])):
        mappings = [tuple(map(int, line.split())) for line in (path / name).read_text().splitlines()]
        require((0, expected, 1) in mappings and all(host > 0 and count > 0 for _inside, host, count in mappings),
                "The payload user namespace maps an unexpected host account.")
    executable = (path / "exe").stat()
    barrier = Path(prepared["barrier"]).stat()
    require((executable.st_dev, executable.st_ino) == (barrier.st_dev, barrier.st_ino),
            "The actual payload did not stop at the trusted executable barrier.")
    require(all(value.startswith("pipe:[") or value == "/dev/null" for value in descriptors),
            "A host file or socket descriptor entered the payload.")
    filesystem(ctx, prepared, pid, mount_rows(path / "mountinfo"), raw_mounts)
    require((path / "stat").read_text().rsplit(")", 1)[1].split()[19] == started,
            "The payload process identity changed during inspection.")
    return {"pid": pid, "start_time": started, "verified": True}
