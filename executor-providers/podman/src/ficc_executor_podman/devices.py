# SPDX-License-Identifier: Apache-2.0
"""Resolve approved NVIDIA UUIDs to exact device nodes and read-only compute libraries."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from ficc.execution.files import fingerprint, identity

SHARED = ("/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools")


def character(path, expected=None):
    info = Path(path).lstat()
    if not stat.S_ISCHR(info.st_mode) or expected is not None and info.st_rdev != expected:
        raise ValueError("An executor character device differs from its approved mapping.")
    return {"source": path, "identity": {**identity(info), "rdev": info.st_rdev}}


def inventory():
    result = {}
    for path in sorted(Path("/proc/driver/nvidia/gpus").glob("*/information")):
        fields: dict[str, list[str]] = {"GPU UUID": [], "Device Minor": [], "Bus Location": []}
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            raw = os.read(fd, 16385)
        finally:
            os.close(fd)
        if len(raw) > 16384 or not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise ValueError("The kernel GPU record is not a bounded regular file.")
        for line in raw.decode("ascii").splitlines():
            name, separator, value = line.partition(":")
            if separator and name.strip() in fields:
                fields[name.strip()].append(value.strip())
        if any(len(values) != 1 for values in fields.values()):
            raise ValueError("The kernel GPU record has incomplete or duplicate identity fields.")
        uuid, minor, location = (fields[name][0] for name in fields)
        if (not re.fullmatch(r"GPU-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", uuid)
                or not re.fullmatch(r"0|[1-9][0-9]{0,2}", minor) or location != path.parent.name or uuid in result):
            raise ValueError("The kernel GPU identity or device minor is invalid.")
        result[uuid] = int(minor)
    return result


class Devices:
    def __init__(self, configuration):
        self.configuration = configuration
        self.mapping: dict[str, dict] = {}
        self.libraries: list[dict] = []
        if configuration is None:
            return
        path = Path(configuration.cdi)
        bound = fingerprint(path)
        if bound["digest"] != configuration.digest or bound["bytes"] > 1024 * 1024:
            raise ValueError("The approved CDI map changed or exceeds 1 MiB.")
        self.source = json.loads(path.read_text())
        if self.source.get("cdiVersion") != "0.7.0" or self.source.get("kind") != "nvidia.com/gpu":
            raise ValueError("The installed NVIDIA CDI version is not qualified.")
        for entry in self.source["devices"]:
            if not re.fullmatch(r"GPU-[0-9a-f-]{36}", entry["name"]):
                continue
            nodes = [item for item in entry["containerEdits"]["deviceNodes"]
                     if re.fullmatch(r"/dev/nvidia[0-9]+", item["path"])]
            if len(nodes) != 1 or entry["name"] in self.mapping or nodes[0].get("major") != 195:
                raise ValueError("The CDI map does not bind each UUID to one NVIDIA character node.")
            self.mapping[entry["name"]] = nodes[0]
        self.shared = {item["path"]: item for item in self.source["containerEdits"]["deviceNodes"]}
        mounts = {item["hostPath"]: item for item in self.source["containerEdits"]["mounts"]}
        for library in configuration.libraries:
            info = fingerprint(Path(library.path))
            if info["digest"] != library.digest:
                raise ValueError("An approved GPU library changed.")
            item = mounts[library.path]
            if item["containerPath"] != library.path or set(item["options"]) != {"ro", "nosuid", "nodev", "rbind", "rprivate"}:
                raise ValueError("A GPU library has unapproved CDI mount edits.")
            self.libraries.append({"source": library.path, "target": library.path, "read_only": True, "identity": info})

    def select(self, uuids):
        current = inventory() if Path("/proc/driver/nvidia/gpus").exists() else {}
        expected = {uuid: item.get("minor", 0) for uuid, item in self.mapping.items()}
        if self.mapping and current != expected:
            raise ValueError("The kernel UUID-to-device mapping changed from the installed CDI map.")
        if any(uuid not in self.mapping or uuid not in current for uuid in uuids):
            raise ValueError("Select only approved physical GPU UUIDs.")
        denied: list[dict] = []
        selected: list[dict] = []
        if not self.mapping:
            denied = [character("/dev/nvidia" + str(minor), os.makedev(195, minor)) for minor in current.values()]
        for uuid, node in self.mapping.items():
            item = character(node["path"], os.makedev(node["major"], node.get("minor", 0)))
            (selected if uuid in uuids else denied).append(item)
        physical = selected[:]
        if uuids:
            for name in SHARED:
                node = self.shared[name]
                selected.append(character(name, os.makedev(node["major"], node.get("minor", 0))))
        mounts = [{**item, "target": item["source"], "read_only": False} for item in selected]
        if uuids:
            for library in self.libraries:
                saved, actual = library["identity"], Path(library["source"]).lstat()
                if any(identity(actual)[key] != saved[key] for key in ("device", "inode", "mode", "bytes", "mtime_ns", "ctime_ns")):
                    raise ValueError("An approved GPU library changed after provider initialization.")
            mounts.extend(self.libraries)
        nodes = [{"path": item["source"], "type": "c", "major": os.major(item["identity"]["rdev"]),
                  "minor": os.minor(item["identity"]["rdev"]), "permissions": "rw"} for item in selected]
        name = hashlib.sha256(json.dumps(sorted(uuids)).encode()).hexdigest()
        cdi = {"cdiVersion": "0.7.0", "kind": "ficc.executor/gpu", "devices": [{"name": name,
               "containerEdits": {"deviceNodes": nodes, "mounts": [{"hostPath": item["source"],
                    "containerPath": item["target"], "options": ["ro", "nosuid", "nodev", "rbind", "rprivate"]}
                    for item in self.libraries]}}]}
        return {"devices": [character("/dev/fuse"), *selected], "mounts": mounts,
                "positive": [item["source"] for item in selected], "negative": [item["source"] for item in denied],
                "physical": physical, "cdi": cdi if uuids else None,
                "cdi_name": "ficc.executor/gpu=" + name if uuids else None}
