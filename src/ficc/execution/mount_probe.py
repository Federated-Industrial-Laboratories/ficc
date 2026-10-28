# SPDX-License-Identifier: Apache-2.0
"""Read bounded payload metadata in a disposable process inside its user namespace."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

FIELDS = ("st_dev", "st_ino", "st_mode", "st_rdev", "st_size", "st_mtime_ns")


def root_identity(fd):
    fields = dict(line.split(":", 1) for line in (Path("/proc/self/fdinfo") / str(fd)).read_text().splitlines() if ":" in line)
    return fields["mnt_id"].strip(), fields["ino"].strip()


def inspect(pid, targets, shared_memory):
    if len(targets) > 1024 or any(not name.startswith("/") or ".." in name.split("/") for name in targets):
        raise ValueError("The payload metadata target set is invalid or oversized.")
    process = Path("/proc") / str(pid)
    started = (process / "stat").read_text().rsplit(")", 1)[1].split()[19]
    root = os.open(process / "root", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    namespace = None
    try:
        namespace = os.open(process / "ns/user", os.O_RDONLY | os.O_CLOEXEC)
        namespace_identity = os.fstat(namespace)
        retained_root = root_identity(root)
        request = json.dumps({"targets": targets, "shared_memory": shared_memory}).encode()
        if len(request) > 65536:
            raise ValueError("The payload metadata request exceeds its bound.")
        result = subprocess.run([sys.executable, "-I", "-B", "-m", "ficc.execution.mount_probe", str(root), str(namespace)],
                                input=request, capture_output=True, pass_fds=(root, namespace), timeout=5, check=False)
        if result.returncode or len(result.stdout) > 512 * 1024:
            raise ValueError("The isolated payload metadata inspection failed.")
        observed = json.loads(result.stdout)
        if set(observed["targets"]) != set(targets):
            raise ValueError("The isolated payload metadata inspection returned different targets.")
        after = os.open(process / "root", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            current_namespace = (process / "ns/user").stat()
            if (root_identity(after) != retained_root or
                    (current_namespace.st_dev, current_namespace.st_ino) != (namespace_identity.st_dev, namespace_identity.st_ino) or
                    (process / "stat").read_text().rsplit(")", 1)[1].split()[19] != started):
                raise ValueError("The payload process, namespace or root changed during metadata inspection.")
        finally:
            os.close(after)
        return {name: SimpleNamespace(**value) for name, value in observed["targets"].items()}, observed["shared_memory_bytes"]
    finally:
        os.close(root)
        if namespace is not None:
            os.close(namespace)


def main():
    request = json.loads(sys.stdin.buffer.read(65537))
    root, namespace = map(int, sys.argv[1:])
    os.setns(namespace, os.CLONE_NEWUSER)
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
    os.fchdir(root)
    os.chroot(".")
    os.chdir("/")
    os.close(root)
    os.close(namespace)
    values = {}
    for name in request["targets"]:
        info = os.lstat(name)
        values[name] = {key: getattr(info, key) for key in FIELDS}
    shared = os.statvfs("/dev/shm") if request["shared_memory"] else None
    print(json.dumps({"targets": values, "shared_memory_bytes": shared.f_blocks * shared.f_frsize if shared else 0}))


if __name__ == "__main__":
    main()
