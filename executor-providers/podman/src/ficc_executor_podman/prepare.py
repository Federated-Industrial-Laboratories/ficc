# SPDX-License-Identifier: Apache-2.0
"""Prepare private runtime state without executing or extracting workload images as root."""

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from ficc.execution.files import atomic, atomic_bytes, directory, fingerprint, identity


def mkdir(path, uid, gid, mode=0o700):
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    path.chmod(mode)


def bind(source, target, read_only=True):
    return {"source": str(source), "target": target, "read_only": read_only,
            "identity": identity(source.lstat())}


def resolver(root):
    path = root / "resolv.conf"
    atomic_bytes(path, b"", 0o444)
    return bind(path, "/etc/resolv.conf")


def copy_input(source, destination, expected, uid, gid, check):
    first = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    second = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        before = os.fstat(first)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or before.st_size != expected["bytes"]:
            raise ValueError("The staged input no longer has its approved identity.")
        value = hashlib.sha256()
        with os.fdopen(os.dup(second), "wb") as output:
            while chunk := os.read(first, 1024 * 1024):
                check()
                value.update(chunk)
                output.write(chunk)
        if "sha256:" + value.hexdigest() != expected["digest"] or identity(before) != identity(os.fstat(first)):
            raise ValueError("The staged input changed while it was copied.")
        os.fsync(second)
        os.fchown(second, uid, gid)
    finally:
        os.close(first)
        os.close(second)


def staged_input(ctx, item, *, owner=0):
    supplied = [value for value in ctx.get("inputs", []) if value["id"] == item["id"]]
    if len(supplied) != 1 or any(supplied[0][name] != item[name] for name in ("id", "name", "bytes", "digest")):
        raise ValueError("The host did not supply the exact completed input capability.")
    saved = supplied[0]
    source = Path(saved["path"])
    directory(source.parent, owner=owner, private=True)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        actual = identity(info)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_gid != ctx["slot"]["gid"]
                or info.st_mode & 0o222 or info.st_nlink not in {1, 2}
                or info.st_dev != ctx["binding"]["device"] or info.st_size != item["bytes"]
                or any(actual[name] != saved["identity"][name] for name in ("device", "inode", "mode", "bytes", "mtime_ns"))):
            raise ValueError("The host-staged input no longer has its immutable reserved identity.")
        return source, actual
    finally:
        os.close(fd)


def link_input(ctx, item, destination, *, owner=0):
    source, before = staged_input(ctx, item, owner=owner)
    os.link(source, destination, follow_symlinks=False)
    _source, after = staged_input(ctx, item, owner=owner)
    linked = identity(destination.lstat())
    if any(linked[name] != after[name] or before[name] != after[name]
           for name in ("device", "inode", "mode", "bytes", "mtime_ns")):
        raise ValueError("The staged input changed while the runtime linked it.")
    parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def verify_inputs(ctx):
    for item in ctx["plan"]["job"]["inputs"]:
        if item.get("delivery", "local") == "stream":
            _source, saved = staged_input(ctx, item)
            actual = identity((Path(ctx["directory"]) / "inputs" / item["name"]).lstat())
            if actual != saved:
                raise ValueError("The runtime input no longer links the host-staged object.")


def create(driver, ctx):
    check = ctx["check"]
    check()
    ctx = {key: value for key, value in ctx.items() if key != "check"}
    root = Path(ctx["directory"])
    uid, gid = ctx["slot"]["uid"], ctx["slot"]["gid"]
    mkdir(root, 0, gid, 0o750)
    runtime = root / "runtime"
    mkdir(runtime, uid, gid)
    for name in ("work", "home", "run", "config", "data", "tmp", "storage", "hooks"):
        mkdir(runtime / name, uid, gid)
    mkdir(root / "control", 0, gid, 0o550)
    mkdir(root / "inputs", 0, gid, 0o550)
    mkdir(root / "cdi", 0, gid, 0o550)
    job = ctx["plan"]["job"]
    image = driver.images[job["runtime"]["image_digest"]]
    local_image = runtime / "image.oci.tar"
    copy_input(image.archive, local_image, {"bytes": driver.identities[image.archive]["bytes"],
               "digest": image.archive_digest}, uid, gid, check)
    for item in job["inputs"]:
        check()
        if item.get("delivery", "local") == "stream":
            link_input(ctx, item, root / "inputs" / item["name"])
            continue
        source = driver.inputs.get(item["id"])
        if source is None or (source.digest, source.bytes) != (item["digest"], item["bytes"]):
            raise ValueError("An input is not staged with the exact approved digest and size.")
        copy_input(source.path, root / "inputs" / item["name"], item, uid, gid, check)
    gpu = driver.devices.select(job["limits"]["gpu_devices"])
    if gpu["cdi"] is not None:
        atomic(root / "cdi/gpu.json", gpu["cdi"], 0o440)
        os.chown(root / "cdi/gpu.json", 0, gid)
    storage = runtime / "config/storage.conf"
    storage.write_text('[storage]\ndriver="overlay"\nrunroot=' + json.dumps(str(runtime / "run/storage")) +
        '\ngraphroot=' + json.dumps(str(runtime / "storage")) +
        '\n[storage.options.overlay]\nmount_program="/usr/bin/fuse-overlayfs"\n')
    os.chown(storage, uid, gid)
    storage.chmod(0o400)
    containers = root / "containers.conf"
    containers.write_text('[engine]\ncgroup_manager="cgroupfs"\nevents_logger="none"\ncdi_spec_dirs=[' +
                          json.dumps(str(root / "cdi")) + ']\nhooks_dir=[' + json.dumps(str(runtime / "hooks")) + ']\n')
    os.chown(containers, 0, gid)
    containers.chmod(0o440)
    barrier = Path(__file__).parent / "barrier"
    fingerprint(barrier)
    mounts = [bind(runtime / "work", "/work", False), bind(root / "inputs", "/inputs"),
              bind(root / "control", "/ficc/control"), bind(barrier, "/ficc/barrier"), resolver(root), *gpu["mounts"]]
    request = {"context": ctx, "image": str(local_image), "image_digest": image.digest,
               "containers_config": str(containers), "barrier": str(barrier), "gpu": gpu}
    atomic(root / "request.json", request, 0o440)
    os.chown(root / "request.json", 0, gid)
    check()
    return {"argv": [sys.executable, "-I", "-B", "-m", "ficc_executor_podman.runner", str(root / "request.json")],
            "devices": gpu["devices"], "mounts": mounts, "barrier": str(barrier),
            "generated_targets": ["/run/.containerenv", "/etc/hostname"],
            "positive_devices": gpu["positive"], "negative_devices": gpu["negative"]}
