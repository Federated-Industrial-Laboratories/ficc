# SPDX-License-Identifier: Apache-2.0
"""Require namespace, syscall and cgroup enforcement for every module process."""

import asyncio
import os
import platform
import re
import secrets
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import Failure
from ..pipe_ready import ready
from .native import require_native
from .protocol import MAX_OUTPUT, MAX_STDERR
from .sandbox_io import Channel
from .watcher import identity

MEMORY_BYTES = 128 * 1024 * 1024
MAX_TASKS = 32
MAX_SECONDS = 10
BROKER_SECONDS = 30
ADAPTER_APPLY_SECONDS = 30
PROPERTIES = {
    "MemoryMax": str(MEMORY_BYTES), "MemorySwapMax": "0", "TasksMax": str(MAX_TASKS),
    "CPUQuota": "50%", "RuntimeMaxSec": "12", "TimeoutStopSec": "1",
    "KillMode": "control-group", "SendSIGKILL": "yes", "NoNewPrivileges": "yes",
    "UMask": "0077", "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes",
    "LockPersonality": "yes", "OOMPolicy": "kill", "SystemCallArchitectures": "native",
    # bwrap configures loopback through netlink inside the private network namespace.
    "RestrictAddressFamilies": "AF_UNIX AF_NETLINK",
    "SystemCallFilter": "~@clock @module @raw-io @reboot @swap @obsolete @keyring",
}
PROBE = """import json,os,socket,sys
status=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
denied=False
try: socket.socket(socket.AF_INET,socket.SOCK_STREAM)
except OSError: denied=True
result={'seccomp':status['Seccomp'].strip(),'nnp':status['NoNewPrivs'].strip(),
        'network_denied':denied,'home_absent':not os.path.exists('/home'),
        'env_safe':set(os.environ)<=set(('PATH','LANG','HOME','TMPDIR','PWD')) and os.environ.get('PWD')=='/module'}
sys.stdin.buffer.read()
print(json.dumps(result),flush=True)
"""


@dataclass(frozen=True)
class SandboxStatus:
    available: bool
    reason: str

    def public(self) -> dict:
        return {"available": self.available, "reason": self.reason}


def environment() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus"}


def require_runtime(manifest: dict, package: Path | None = None) -> None:
    """Check the platform and available loaders without running package code."""
    runtime = manifest["runtime"]
    if runtime["kind"] == "declarative":
        return
    if runtime.get("platform") != platform.system().lower():
        raise Failure("module_runtime_unavailable", "This module targets a different operating system.", 409)
    if runtime.get("architecture") not in ("any", platform.machine()):
        raise Failure("module_runtime_unavailable", "This module targets a different architecture.", 409)
    if runtime["kind"] == "native":
        if package is not None:
            require_native(package, runtime)
        return
    binary = {"python": "/usr/bin/python3", "javascript": "/usr/bin/node"}.get(runtime["kind"])
    if binary is None:
        raise Failure("module_runtime_unavailable", "The requested module runtime is unavailable.", 503)
    if not os.access(binary, os.X_OK):
        raise Failure("module_runtime_unavailable", f"The module requires an executable {binary}.", 503)


def entry_command(manifest: dict) -> list[str]:
    require_runtime(manifest)
    runtime = manifest["runtime"]
    path = "/module/" + runtime["entry"]
    if runtime["kind"] == "native":
        return [path]
    binary = {"python": "/usr/bin/python3", "javascript": "/usr/bin/node"}[runtime["kind"]]
    return [binary, "-I", path] if runtime["kind"] == "python" else [binary, "--no-addons", path]


def command(package: Path, executable: list[str], unit: str, *, adapter_apply: bool = False,
            provider_socket: Path | None = None, watcher: Path | None = None,
            broker_request: bool = False) -> list[str]:
    for binary in ("/usr/bin/bwrap", "/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/python3"):
        if not os.access(binary, os.X_OK):
            raise Failure("module_sandbox_unavailable", "The required sandbox tools are unavailable.", 503)
    isolated = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session",
                "--cap-drop", "ALL", "--clearenv", "--ro-bind", "/usr", "/usr"]
    for name in ("lib", "lib64", "bin", "sbin"):
        if Path("/" + name).exists():
            isolated += ["--ro-bind", "/" + name, "/" + name]
    isolated += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                 "--ro-bind", str(package.resolve()), "/module", "--chdir", "/module",
                 "--hostname", "ficc-module"]
    if provider_socket is not None:
        isolated += ["--dir", "/provider", "--ro-bind", str(provider_socket), "/provider/socket"]
    for key, value in {"PATH": "/usr/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent", "TMPDIR": "/tmp"}.items():
        isolated += ["--setenv", key, value]
    isolated += ["--", *executable]
    launch = ["/usr/bin/systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect",
              "--service-type=exec", "--unit=" + unit]
    properties = PROPERTIES
    if adapter_apply or broker_request:
        seconds = ADAPTER_APPLY_SECONDS if adapter_apply else BROKER_SECONDS
        properties = {**PROPERTIES, "RuntimeMaxSec": str(seconds + 2)}
    launch += [f"--property={key}={value}" for key, value in properties.items()]
    return launch + ["--", "/usr/bin/python3", "-I", str(watcher or Path(__file__).with_name("watcher.py")),
                     str(os.getpid()), identity(os.getpid()), "--", *isolated]


async def management(*arguments: str) -> tuple[int, bytes]:
    """Read bounded service metadata without thread-pool wakeup dependencies."""
    process = subprocess.Popen(["/usr/bin/systemctl", "--user", *arguments],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=environment(),
                               start_new_session=True, close_fds=True)
    assert process.stdout is not None
    pidfd = None
    data = bytearray()
    try:
        pidfd = os.pidfd_open(process.pid)
        os.set_blocking(process.stdout.fileno(), False)
        async with asyncio.timeout(4):
            while True:
                try:
                    chunk = os.read(process.stdout.fileno(), 4096)
                except BlockingIOError:
                    await ready(process.stdout.fileno())
                    continue
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > 16384:
                    raise Failure("module_sandbox_unavailable", "Service metadata exceeds its limit.", 503)
            await ready(pidfd)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if pidfd is not None:
            await ready(pidfd)
        code = process.wait()
        process.stdout.close()
        if pidfd is not None:
            os.close(pidfd)
    return code, bytes(data)


async def finish_cleanup(operation) -> None:
    """Do not detach cleanup when a second cancellation arrives during service stop."""
    task = asyncio.create_task(operation)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    task.result()
    if cancelled:
        raise asyncio.CancelledError


async def enforcement(unit: str) -> Path:
    required = ("MemoryMax", "MemorySwapMax", "TasksMax", "NoNewPrivileges", "KillMode", "ControlGroup")
    code, data = await management("show", unit, *["--property=" + key for key in required])
    values = dict(line.split("=", 1) for line in data.decode("utf-8").splitlines() if "=" in line)
    if code or any(values.get(key) != PROPERTIES[key] for key in required[:-1]):
        raise Failure("module_sandbox_unavailable", "The module resource controls are not active.", 503)
    group = values.get("ControlGroup", "")
    if not re.fullmatch(r"/[a-zA-Z0-9_.@:/-]+", group) or ".." in group.split("/"):
        raise Failure("module_sandbox_unavailable", "The module control group is unavailable.", 503)
    root = Path("/sys/fs/cgroup") / group.lstrip("/")
    try:
        limits = {name: (root / name).read_text().strip() for name in
                  ("memory.max", "memory.swap.max", "pids.max", "cpu.max")}
        quota, period = limits["cpu.max"].split()
        if (limits["memory.max"] != str(MEMORY_BYTES) or limits["memory.swap.max"] != "0"
                or limits["pids.max"] != str(MAX_TASKS) or int(quota) * 2 > int(period)):
            raise ValueError("Resource limits differ")
    except (OSError, ValueError) as exc:
        raise Failure("module_sandbox_unavailable", "The kernel resource controls are unavailable.", 503) from exc
    return root


async def stop_service(unit: str, group: Path | None) -> None:
    """Confirm an admitted service has no live processes before releasing its lease."""
    try:
        await management("stop", unit)
    except (TimeoutError, OSError):
        if group is None:
            raise Failure("module_cleanup_failed", "The module service stop could not be checked.", 503)
    if group is None:
        return
    # RuntimeMaxSec is an independent backstop if the bus stops responding.
    async with asyncio.timeout(15):
        while True:
            try:
                events = (group / "cgroup.events").read_text().splitlines()
            except FileNotFoundError:
                return
            if "populated 0" in events:
                return
            await asyncio.sleep(0.05)


async def execute(package: Path, executable: list[str], payload: bytes, check, *, conversation=None,
                  adapter_apply: bool = False, provider_socket: Path | None = None,
                  watcher: Path | None = None) -> bytes:
    """Run one service and stop its complete cgroup on every exit path."""
    unit = "ficc-module-" + secrets.token_hex(16) + ".service"
    options: dict[str, Any] = {}
    if adapter_apply:
        options["adapter_apply"] = True
    elif conversation is not None:
        options["broker_request"] = True
    if provider_socket is not None:
        options["provider_socket"] = provider_socket
    if watcher is not None:
        options["watcher"] = watcher
    args = command(package, executable, unit, **options)
    try:
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, bufsize=0,
                                   env=environment(), close_fds=True)
    except OSError as exc:
        raise Failure("module_sandbox_unavailable", "The module sandbox could not start.", 503) from exc
    assert process.stdin and process.stdout and process.stderr
    pipes = (process.stdin, process.stdout, process.stderr)
    tasks: list[asyncio.Task] = []
    pidfd = None
    group: Path | None = None
    exited = asyncio.Event()
    admitted = asyncio.Event()
    channel = Channel(pipes[0], pipes[1], len(payload), conversation.cancel) if conversation else None
    completed = False

    async def read(fd: int, maximum: int):
        result = bytearray()
        while True:
            try:
                chunk = os.read(fd, 16384)
            except BlockingIOError:
                await ready(fd)
                continue
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > maximum:
                raise Failure("module_output_limit", "The module output exceeds its limit.", 502)

    async def write():
        nonlocal group
        try:
            # The unit may not exist yet while systemd-run negotiates creation.
            for attempt in range(20):
                try:
                    group = await enforcement(unit)
                    break
                except Failure:
                    if attempt == 19 or exited.is_set():
                        raise
                    await asyncio.sleep(0.05)
            check()
            offset = 0
            while offset < len(payload):
                try:
                    offset += os.write(pipes[0].fileno(), payload[offset:offset + 8192])
                except BlockingIOError:
                    await ready(pipes[0].fileno(), writing=True)
            admitted.set()
        except BrokenPipeError as exc:
            raise Failure("module_failed", "The module closed its input before the request.", 502) from exc
        finally:
            if channel is None:
                pipes[0].close()

    async def exchange():
        await admitted.wait()
        return await conversation.exchange(channel)

    async def watch():
        assert pidfd is not None
        await ready(pidfd)
        exited.set()

    async def guard():
        while not exited.is_set():
            check()
            try:
                await asyncio.wait_for(exited.wait(), 0.1)
            except TimeoutError:
                pass

    try:
        pidfd = os.pidfd_open(process.pid)
        for pipe in pipes:
            os.set_blocking(pipe.fileno(), False)
        stdout = asyncio.create_task(exchange() if channel else read(pipes[1].fileno(), MAX_OUTPUT))
        tasks = [stdout, asyncio.create_task(read(pipes[2].fileno(), MAX_STDERR)),
                 asyncio.create_task(write()), asyncio.create_task(watch()), asyncio.create_task(guard())]
        seconds = ADAPTER_APPLY_SECONDS if adapter_apply else BROKER_SECONDS if conversation is not None else MAX_SECONDS
        async with asyncio.timeout(seconds):
            await asyncio.gather(*tasks)
        output = stdout.result()
        completed = True
    except TimeoutError as exc:
        raise Failure("module_timeout", "The module operation exceeded its time limit.", 504) from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Failure("module_sandbox_unavailable", "The module could not be supervised.", 503) from exc
    finally:
        async def cleanup():
            if channel is not None and not completed:
                channel.cancel_nowait()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            try:
                # The watcher and systemd own descendants beyond process groups.
                await stop_service(unit, group)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if pidfd is not None:
                    await ready(pidfd)
                process.wait()
                for pipe in pipes:
                    pipe.close()
                if pidfd is not None:
                    os.close(pidfd)

        await finish_cleanup(cleanup())
    code = process.returncode
    if code:
        raise Failure("module_failed", "The isolated module exited with an error.", 502)
    check()
    return output


class Sandbox:
    async def probe(self) -> SandboxStatus:
        import json

        try:
            with tempfile.TemporaryDirectory(prefix="ficc-module-probe-") as directory:
                output = await execute(Path(directory), ["/usr/bin/python3", "-I", "-c", PROBE],
                                       b"", lambda: None)
            value = json.loads(output)
            if value != {"seccomp": "2", "nnp": "1", "network_denied": True,
                         "home_absent": True, "env_safe": True}:
                raise ValueError("Sandbox evidence differs")
        except (Failure, OSError, ValueError, subprocess.TimeoutExpired) as exc:
            reason = exc.message if isinstance(exc, Failure) else "The sandbox check failed."
            return SandboxStatus(False, reason)
        return SandboxStatus(True, "Namespace, syscall and resource controls are active.")
