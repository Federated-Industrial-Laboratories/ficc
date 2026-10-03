# SPDX-License-Identifier: Apache-2.0
"""Implement the trusted batched rootless Podman executor provider."""

import os
import shutil
from pathlib import Path

from ficc.execution import outputs
from ficc.execution.files import fingerprint, identity, read_json
from ficc.execution.protocol import Read
from ficc.execution.storage import mount_rows

from .configuration import Configuration
from .devices import Devices
from .prepare import create, verify_inputs

API_VERSION = 1


class Driver:
    def __init__(self, configuration):
        self.configuration = Configuration.model_validate(configuration)
        self.images = {item.digest: item for item in self.configuration.images}
        self.inputs = {item.id: item for item in self.configuration.inputs}
        self.identities = {}
        for item in self.configuration.images:
            saved = fingerprint(Path(item.archive))
            if saved["digest"] != item.archive_digest:
                raise ValueError("An approved image archive changed.")
            self.identities[item.archive] = saved
        for source in self.configuration.inputs:
            saved = fingerprint(Path(source.path))
            if (saved["digest"], saved["bytes"]) != (source.digest, source.bytes):
                raise ValueError("A staged input changed.")
            self.identities[source.path] = saved
        self.devices = Devices(self.configuration.gpu)

    def probe(self, rows):
        replies = []
        for ctx in rows:
            runtime = ctx["plan"]["job"]["runtime"]
            if runtime["isolation"] != "shared-kernel" or runtime["network"] != "none":
                raise ValueError("This provider supports only shared-kernel isolation without a workload network.")
            if runtime["image_digest"] not in self.images:
                raise ValueError("The image digest is not installed in this executor.")
            for path, saved in self.identities.items():
                if any(identity(Path(path).lstat())[key] != saved[key] for key in
                       ("device", "inode", "mode", "bytes", "mtime_ns", "ctime_ns")):
                    raise ValueError("An approved runtime input changed after provider initialization.")
            self.devices.select(ctx["plan"]["job"]["limits"]["gpu_devices"])
            replies.append({"ready": True})
        return replies

    def prepare(self, rows):
        self.probe(rows)
        return [create(self, ctx) for ctx in rows]

    def start(self, rows):
        self.probe(rows)
        for ctx in rows:
            verify_inputs(ctx)
        return [ctx["prepared"] for ctx in rows]

    def observe(self, rows):
        replies = []
        for ctx in rows:
            root = Path(ctx["directory"]) / "runtime"
            state = read_json(root / "state.json", 65536) if (root / "state.json").exists() else {"phase": "waiting"}
            sizes = {}
            for name in ("stdout", "stderr"):
                path = root / name
                sizes[name + "_bytes"] = path.lstat().st_size if path.exists() else 0
            replies.append({**state, **sizes})
        return replies

    def stop(self, rows):
        return self.observe(rows)

    def collect(self, rows):
        return [outputs.collect(row, Read.model_validate(row["read"]), row["cleanup_confirmed"]) for row in rows]

    def release(self, rows):
        replies = []
        for ctx in rows:
            path = Path(ctx["directory"])
            if path.exists():
                if path.lstat().st_uid != 0 or path.is_symlink() or path.parent.stat().st_dev != ctx["binding"]["device"]:
                    raise ValueError("The attempt directory no longer has its reserved identity.")
                if any(row["target"] == str(path) or row["target"].startswith(str(path) + "/") for row in mount_rows()):
                    raise ValueError("The attempt still has a host mount. Keep its reservation.")
                if not shutil.rmtree.avoids_symlink_attacks:
                    raise ValueError("This platform cannot remove a workload directory without following links.")
                shutil.rmtree(path)
                parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            replies.append({"released": True})
        return replies


def configure(configuration):
    return Driver(configuration)
