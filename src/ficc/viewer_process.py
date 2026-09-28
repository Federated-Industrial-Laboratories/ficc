# SPDX-License-Identifier: Apache-2.0
"""Own one native viewer with private networking, bounded resources and pipes."""

import asyncio
import os
import re
import secrets
import signal
import subprocess
from pathlib import Path

from .errors import Failure
from .modules.sandbox import PROPERTIES, environment, finish_cleanup, management, stop_service
from .modules.watcher import identity
from .native_runtime import validate
from .process import ready
from .viewer.wire import HEADER, MAX_FRAME, frame

MEMORY = 512 * 1024 * 1024
LIMITS = {**PROPERTIES, "MemoryMax": str(MEMORY), "TasksMax": "64", "CPUQuota": "100%",
          "RuntimeMaxSec": "3610", "RestrictAddressFamilies": "AF_UNIX AF_NETLINK AF_INET"}


def command(runtime, unit, protocol="vnc"):
    processors = sorted(os.sched_getaffinity(0))
    processor = processors[int(unit.removeprefix("ficc-viewer-").removesuffix(".service"), 16) % len(processors)]
    runtime = Path(runtime).absolute()
    try:
        manifest = validate(runtime)
    except (OSError, ValueError) as exc:
        raise Failure("viewer_unavailable", "The native display runtime is invalid or incompatible with this host.", 503) from exc
    if protocol not in manifest["protocols"]:
        raise Failure("viewer_protocol_unavailable", "Install a native viewer runtime that includes the required display protocol.", 503)
    binary = runtime / "sbin/guacd"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise Failure("viewer_unavailable", "The native viewer runtime is unavailable.", 503)
    source = Path(__file__).with_name("viewer").resolve()
    isolated = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session",
                "--cap-drop", "ALL", "--clearenv", "--ro-bind", "/usr", "/usr"]
    for name in ("lib", "lib64", "bin", "sbin"):
        if Path("/" + name).exists():
            isolated += ["--ro-bind", "/" + name, "/" + name]
    isolated += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/tmp/viewer",
                 "--ro-bind", str(runtime), "/viewer", "--ro-bind", str(source), "/viewer-code/viewer",
                 "--chdir", "/viewer-code", "--hostname", "ficc-viewer"]
    if Path("/etc/fonts").is_dir():
        isolated += ["--ro-bind", "/etc/fonts", "/etc/fonts"]
    for key, value in {"PATH": "/usr/bin", "LANG": "C.UTF-8", "HOME": "/tmp/viewer", "TMPDIR": "/tmp",
                       "XDG_CONFIG_HOME": "/tmp/viewer/.config",
                       "LD_LIBRARY_PATH": "/viewer/lib:/viewer/lib/x86_64-linux-gnu"}.items():
        isolated += ["--setenv", key, value]
    isolated += ["--", "/usr/bin/python3", "-I", "-c",
                 "import sys,asyncio;sys.path.insert(0,'/viewer-code');from viewer.worker import main;asyncio.run(main())"]
    watcher = Path(__file__).with_name("modules") / "watcher.py"
    return ["/usr/bin/systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect",
            "--service-type=exec", "--unit=" + unit,
            *[f"--property={key}={value}" for key, value in LIMITS.items()],
            f"--property=CPUAffinity={processor}", "--",
            "/usr/bin/python3", "-I", str(watcher), str(os.getpid()), identity(os.getpid()), "--", *isolated]


async def enforcement(unit):
    required = ("MemoryMax", "MemorySwapMax", "TasksMax", "NoNewPrivileges", "KillMode", "ControlGroup")
    code, data = await management("show", unit, *["--property=" + key for key in required])
    values = dict(line.split("=", 1) for line in data.decode().splitlines() if "=" in line)
    if code or any(values.get(key) != LIMITS[key] for key in required[:-1]):
        raise ValueError("Viewer service limits are unavailable.")
    group = values.get("ControlGroup", "")
    if not re.fullmatch(r"/[a-zA-Z0-9_.@:/-]+", group) or ".." in group.split("/"):
        raise ValueError("Invalid viewer control group.")
    path = Path("/sys/fs/cgroup") / group.lstrip("/")
    for name, expected in (("memory.max", str(MEMORY)), ("memory.swap.max", "0"), ("pids.max", "64")):
        if (path / name).read_text().strip() != expected:
            raise ValueError("Viewer kernel limits are unavailable.")
    quota, period = (path / "cpu.max").read_text().split()
    if quota == "max" or int(quota) > int(period):
        raise ValueError("Viewer CPU limit is unavailable.")
    return path


class ViewerProcess:
    def __init__(self, runtime, *, protocol="vnc"):
        self.unit = "ficc-viewer-" + secrets.token_hex(16) + ".service"
        self.process = subprocess.Popen(command(runtime, self.unit, protocol), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, bufsize=0,
            env=environment(), close_fds=True)
        assert self.process.stdin and self.process.stdout and self.process.stderr
        self.pipes = (self.process.stdin, self.process.stdout, self.process.stderr)
        for pipe in self.pipes:
            os.set_blocking(pipe.fileno(), False)
        self.group = None
        self.lock = asyncio.Lock()
        self.closed = False
        self.errors = asyncio.create_task(self.drain_errors())

    async def start(self, check):
        try:
            async with asyncio.timeout(8):
                while True:
                    check()
                    if self.process.poll() is not None:
                        raise ValueError("Viewer process exited during setup.")
                    try:
                        self.group = await enforcement(self.unit)
                        break
                    except (OSError, ValueError):
                        await asyncio.sleep(0.05)
        except BaseException:
            await self.close()
            raise

    async def drain_errors(self):
        size = 0
        while True:
            try:
                data = os.read(self.pipes[2].fileno(), 4096)
            except BlockingIOError:
                await ready(self.pipes[2].fileno())
                continue
            if not data:
                return
            size += len(data)
            if size > 32768:
                raise Failure("viewer_output_limit", "The viewer diagnostic output exceeds its limit.", 502)

    async def readexactly(self, size):
        if not 0 < size <= MAX_FRAME:
            raise ValueError("Invalid viewer read size.")
        data = bytearray()
        while len(data) < size:
            try:
                block = os.read(self.pipes[1].fileno(), size - len(data))
            except BlockingIOError:
                await ready(self.pipes[1].fileno())
                continue
            if not block:
                raise EOFError("The viewer process closed.")
            data.extend(block)
        return bytes(data)

    async def receive(self):
        kind, size = HEADER.unpack(await self.readexactly(HEADER.size))
        if not 1 <= kind <= 5:
            raise ValueError("Invalid viewer message kind.")
        return kind, await self.readexactly(size)

    async def send(self, kind, data):
        packet = frame(kind, data)
        async with self.lock, asyncio.timeout(10):
            offset = 0
            while offset < len(packet):
                try:
                    offset += os.write(self.pipes[0].fileno(), packet[offset:offset + 8192])
                except BlockingIOError:
                    await ready(self.pipes[0].fileno(), writing=True)

    async def close(self):
        if self.closed:
            return
        self.closed = True

        async def cleanup():
            try:
                await stop_service(self.unit, self.group)
            finally:
                self.errors.cancel()
                await asyncio.gather(self.errors, return_exceptions=True)
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait()
                for pipe in self.pipes:
                    pipe.close()
        await finish_cleanup(cleanup())
