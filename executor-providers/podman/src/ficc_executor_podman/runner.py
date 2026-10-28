# SPDX-License-Identifier: Apache-2.0
"""Run the fixed rootless engine below the system-owned attempt resource envelope."""

import errno
import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path

from ficc.execution.files import atomic, read_json


def environment(root, request):
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
            "HOME": str(root / "home"), "XDG_RUNTIME_DIR": str(root / "run"),
            "XDG_CONFIG_HOME": str(root / "config"), "XDG_DATA_HOME": str(root / "data"),
            "TMPDIR": str(root / "tmp"), "CONTAINERS_STORAGE_CONF": str(root / "config/storage.conf"),
            "CONTAINERS_CONF": request["containers_config"]}


def arguments(request):
    ctx = request["context"]
    root = Path(ctx["directory"])
    args = ["create", "--name=ficc-" + ctx["plan"]["attempt_id"], "--pull=never", "--network=none",
            "--read-only", "--read-only-tmpfs=false", "--image-volume=ignore", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--hooks-dir=" + str(root / "runtime/hooks"),
            "--log-driver=none", "--http-proxy=false", "--no-hosts", "--hostname=ficc-work",
            "--ipc=private", "--cgroupns=private", "--cgroups=enabled", "--cgroup-parent=" + ctx["cgroup"],
            "--user=0:0", "--workdir=/work", "--entrypoint=/ficc/barrier"]
    for source, target, flags in ((root / "runtime/work", "/work", "rw,nosuid,nodev"),
                                  (root / "inputs", "/inputs", "ro,nosuid,nodev"),
                                  (root / "control", "/ficc/control", "ro,nosuid,nodev"),
                                  (root / "resolv.conf", "/etc/resolv.conf", "ro,nosuid,nodev"),
                                  (Path(request["barrier"]), "/ficc/barrier", "ro,nosuid,nodev")):
        args.append("--volume=" + str(source) + ":" + target + ":" + flags)
    if request.get("socket_proxy"):
        args.append("--volume=" + request["socket_proxy"] + ":/ficc/socket-proxy:ro,nosuid,nodev")
        # Private shared memory is charged to the existing cgroup memory ceiling.
        args.append("--tmpfs=/dev/shm:rw,nosuid,nodev,noexec,size=" + str(min(1024 * 1024 * 1024, ctx["plan"]["job"]["limits"]["memory_bytes"] // 4)) + ",mode=1777")
    if request["gpu"]["cdi_name"] is not None:
        args.append("--device=" + request["gpu"]["cdi_name"])
    for name, value in ctx["plan"]["job"]["payload"]["environment"].items():
        args.extend(["--env", name + "=" + value])
    return args + [request["image_digest"], "--", *ctx["plan"]["job"]["payload"]["argv"]]


def device_probe(request):
    rows = []
    for key, expected in (("positive", 0), ("negative", errno.EPERM)):
        for name in request["gpu"][key]:
            try:
                fd = os.open(name, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
            except OSError as exc:
                code = exc.errno
            else:
                os.close(fd)
                code = 0
            rows.append({"path": name, "errno": code, "expected": expected})
    return rows


class Engine:
    def __init__(self, request):
        self.root = Path(request["context"]["directory"]) / "runtime"
        self.environment = environment(self.root, request)
        self.prefix = ["/usr/bin/podman", "--cgroup-manager=cgroupfs", "--events-backend=none",
                       "--runtime=/usr/bin/crun", "--root=" + str(self.root / "storage"),
                       "--runroot=" + str(self.root / "run/storage"), "--tmpdir=" + str(self.root / "tmp/podman")]
        if request["context"]["plan"]["job"].get("endpoint"):
            # An explicit root clears the storage options from storage.conf.
            self.prefix.extend(["--storage-driver=overlay",
                                "--storage-opt=overlay.mount_program=/usr/bin/fuse-overlayfs"])

    def call(self, argv, *, timeout=30, pass_fds=()):
        try:
            with (self.root / "engine.stdout").open("wb") as output, (self.root / "engine.stderr").open("ab") as error:
                result = subprocess.run(self.prefix + argv, stdin=subprocess.DEVNULL, stdout=output,
                                        stderr=error, env=self.environment, timeout=timeout, check=False, pass_fds=pass_fds)
            if result.returncode:
                raise ValueError("The rootless engine " + argv[0] + " operation failed.")
        except (subprocess.TimeoutExpired, ValueError) as exc:
            message = ("The rootless engine " + argv[0] + " operation exceeded its " + str(timeout) + " second bound."
                       if isinstance(exc, subprocess.TimeoutExpired) else str(exc))
            with (self.root / "stderr").open("ab") as diagnostic:
                diagnostic.write((message + "\n").encode())
            raise ValueError(message) from None
        with (self.root / "engine.stdout").open("rb") as source:
            value = source.read(65537)
        if len(value) > 65536:
            raise ValueError("The rootless engine returned an oversized control message.")
        return value.decode("utf-8")

    def drain(self, process):
        selector = selectors.DefaultSelector()
        outputs = {}
        try:
            for name in ("stdout", "stderr"):
                outputs[name] = (self.root / name).open("wb")
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                for key, _ in selector.select(0.1):
                    data = os.read(key.fd, 65536)
                    if data:
                        outputs[key.data].write(data)
                        outputs[key.data].flush()
                    else:
                        selector.unregister(key.fileobj)
                        getattr(process, key.data).close()
            return process.wait()
        finally:
            selector.close()
            for output in outputs.values():
                output.close()
            if process.poll() is None:
                process.kill()
                process.wait()
            for name in outputs:
                getattr(process, name).close()


def run(request):
    ctx = request["context"]
    root = Path(ctx["directory"])
    if os.getuid() == 0 or os.getuid() != ctx["slot"]["uid"] or os.getgid() != ctx["slot"]["gid"]:
        raise ValueError("The rootless runner requires the recorded workload account.")
    if Path("/proc/self/cgroup").read_text().strip() != "0::" + ctx["cgroup"] + "/manager":
        raise ValueError("The runner is outside its delegated child cgroup.")
    state_path = root / "runtime/state.json"
    atomic(state_path, {"phase": "ready", "runner_pid": os.getpid(), "device_probe": device_probe(request)})
    while not (root / "control/launch").exists():
        time.sleep(0.02)
    group = Path("/sys/fs/cgroup") / ctx["cgroup"].lstrip("/")
    (group / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    engine = Engine(request)
    if request.get("image_identity") is not None:
        from ficc.execution.files import identity
        fd = os.open(request["image"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o222 or identity(info) != request["image_identity"]:
                raise ValueError("The approved shared image archive changed identity.")
            engine.call(["load", "--input", "/proc/self/fd/" + str(fd)], timeout=None, pass_fds=(fd,))
        finally:
            os.close(fd)
    else:
        engine.call(["load", "--input", request["image"]], timeout=None)
    actual = engine.call(["image", "inspect", request["image_digest"], "--format", "{{.Id}}"]).strip()
    if actual.removeprefix("sha256:") != request["image_digest"].removeprefix("sha256:"):
        raise ValueError("The loaded image does not have the exact approved digest.")
    container = engine.call(arguments(request)).strip()
    if len(container) != 64 or any(value not in "0123456789abcdef" for value in container):
        raise ValueError("The engine did not return a container identity.")
    process = subprocess.Popen(engine.prefix + ["start", "--attach", container], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=engine.environment)
    try:
        while process.poll() is None:
            value = engine.call(["inspect", container, "--format", "{{.State.Pid}}"]).strip()
            if value.isdigit() and int(value) > 1:
                atomic(state_path, {"phase": "payload", "payload_pid": int(value), "container": container})
                break
            time.sleep(0.02)
        else:
            raise ValueError("The engine did not expose a live payload for inspection.")
        engine.drain(process)
        final = json.loads(engine.call(["inspect", container, "--format", "{{json .State}}"] ))
        code = final.get("ExitCode")
        if final.get("Status") != "exited" or type(code) is not int or not 0 <= code <= 255:
            raise ValueError("The engine did not retain a complete payload outcome.")
        atomic(state_path, {"phase": "finished", "exit_code": code, "container": container})
        return 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main():
    if len(sys.argv) != 2:
        return 2
    try:
        request = read_json(Path(sys.argv[1]))
        return run(request)
    except Exception as error:
        reason = str(error)[:512] if isinstance(error, ValueError) else type(error).__name__
        sys.stderr.write("The executor runtime control failed: " + reason + ". Inspect the reserved slot.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
