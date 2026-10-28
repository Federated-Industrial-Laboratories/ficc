# SPDX-License-Identifier: Apache-2.0
"""Bind a userspace overlay to its trusted helper and reserved backing directories."""

import os
import stat
from pathlib import Path

from .files import identity
from .storage import processes


def require(value, message):
    if not value:
        raise ValueError(message)


def backing(ctx, main, path):
    """Read the live helper's kernel connection and already-open backing directories."""
    major, minor = map(int, main["device"].split(":"))
    require(major == 0, "The userspace overlay has an unexpected device identity.")
    root = Path(ctx["directory"]) / "runtime/storage"
    descriptors = list((path / "fd").iterdir())
    require(len(descriptors) <= 4096, "The overlay helper descriptor set exceeds its inspection bound.")
    connections, directories = [], []
    for descriptor in descriptors:
        info = descriptor.stat()
        if stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(10, 229):
            fields = dict(line.split(":", 1) for line in (path / "fdinfo" / descriptor.name).read_text().splitlines() if ":" in line)
            connections.append(fields.get("fuse_connection", "").strip())
        elif stat.S_ISDIR(info.st_mode):
            target = Path(os.readlink(descriptor))
            require(target.is_absolute() and target.is_relative_to(root) and ".." not in target.parts
                    and info.st_dev == ctx["binding"]["device"],
                    "The overlay helper has backing storage outside the reserved filesystem.")
            current = target.resolve(strict=True)
            require(current.is_relative_to(root) and (current.stat().st_dev, current.stat().st_ino) == (info.st_dev, info.st_ino),
                    "An overlay backing directory changed identity or escaped its reservation.")
            directories.append({"path": str(current), "device": info.st_dev, "inode": info.st_ino})
    require(connections == [str(minor)],
            "The kernel cannot bind the overlay helper to the payload FUSE connection.")
    require(len(directories) >= 3, "The overlay helper did not retain its lower, upper and work directories.")
    return directories


def verify(ctx, prepared, main):
    saved = prepared.get("overlay_helper")
    require(isinstance(saved, dict), "The userspace overlay has no approved helper identity.")
    executable = Path("/usr/bin/fuse-overlayfs")
    current = executable.stat()
    require(current.st_uid == 0 and not current.st_mode & 0o022
            and all(identity(current)[key] == saved[key] for key in identity(current)),
            "The approved overlay helper changed identity.")
    matched = []
    for pid in processes(ctx["slot"]["uid"]):
        path = Path("/proc") / str(pid)
        try:
            observed = (path / "exe").stat()
            if (observed.st_dev, observed.st_ino) != (saved["device"], saved["inode"]):
                continue
            started = (path / "stat").read_text().rsplit(")", 1)[1].split()[19]
            group = (path / "cgroup").read_text().strip()
            if not group.startswith("0::" + ctx["cgroup"] + "/"):
                continue
            status = dict(line.split(":", 1) for line in (path / "status").read_text().splitlines() if ":" in line)
            require([int(value) for value in status["Uid"].split()] == [ctx["slot"]["uid"]] * 4
                    and [int(value) for value in status["Gid"].split()] == [ctx["slot"]["gid"]] * 4,
                    "The overlay helper has an unexpected host account.")
            directories = backing(ctx, main, path)
            require((path / "stat").read_text().rsplit(")", 1)[1].split()[19] == started,
                    "The overlay helper changed process identity during inspection.")
            matched.append({"pid": pid, "start_time": started, "device": main["device"], "directories": directories})
        except (FileNotFoundError, ProcessLookupError):
            continue
    require(len(matched) == 1, "The payload root does not have one verified reserved overlay helper.")
    return matched[0]
