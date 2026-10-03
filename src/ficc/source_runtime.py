# SPDX-License-Identifier: Apache-2.0
"""Supervise bounded data workers using the existing cgroup lifecycle controls."""

import asyncio
import json
import os
import secrets
import signal
import subprocess
import sys
from pathlib import Path

from .data_sdk import MAX_FRAME, encoded, load
from .errors import Failure
from .modules import watcher
from .modules.sandbox import PROPERTIES, enforcement, environment, finish_cleanup, stop_service
from .pipe_ready import ready


def command(packet, limits, unit):
    properties = {**PROPERTIES, "MemoryMax": str(limits["memory_bytes"]), "RuntimeMaxSec": str(limits["seconds"] + 2)}
    network = packet.get("endpoint") is not None
    if network:
        properties["RestrictAddressFamilies"] = "AF_UNIX AF_INET AF_INET6 AF_NETLINK"
    isolated = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"]
    if network:
        # Installed deployment drivers are trusted to use their pinned endpoint.
        # This namespace protects state files; it is not a hostile-code egress jail.
        isolated += ["--share-net"]
    mounts = {Path("/usr"), Path(sys.prefix).absolute(), Path(__file__).parents[1]}
    paths = {str(Path(__file__).parents[1])}
    import ficc_node
    mounts.add(Path(ficc_node.__file__).parents[1])
    paths.add(str(Path(ficc_node.__file__).parents[1]))
    for name, group in ((packet["provider"], "ficc.data"), (packet.get("format"), "ficc.format")):
        if name and name != "original":
            module, _ = load(name, group)
            folder = Path(module.__file__).parents[1]
            mounts.add(folder)
            paths.add(str(folder))
    for path in (Path("/lib"), Path("/lib64"), Path("/bin"), Path("/etc/ssl/certs")):
        if path.exists():
            mounts.add(path)
    for path in sorted(mounts, key=str):
        isolated += ["--ro-bind", str(path), str(path)]
    isolated += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/work", "--chdir", "/work"]
    if packet.get("source"):
        from ficc_node.file_access import parts
        relative = os.fsdecode(b"/".join(parts(packet["source"]["reference"])))
        isolated += ["--ro-bind", packet["source"]["root"]["path"], "/input"]
        # Pin the selected inode in the namespace as well as its parent root.
        # Native libraries reopening by path cannot race a replaced source file.
        isolated += ["--ro-bind", str(Path(packet["source"]["root"]["path"]) / relative), "/input/" + relative]
        packet = {**packet, "source": {**packet["source"], "root": {**packet["source"]["root"], "path": "/input"}}}
    if packet.get("part_receipts"):
        isolated += ["--ro-bind", packet["part_receipts"], "/part-receipts.ndjson"]
        packet = {**packet, "part_receipts": "/part-receipts.ndjson"}
    for key, value in {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent", "TMPDIR": "/tmp",
                       "PYTHONPATH": ":".join(sorted(paths)), "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"}.items():
        isolated += ["--setenv", key, value]
    isolated += ["--", sys.executable, "-m", "ficc.data_worker"]
    launch = ["/usr/bin/systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect", "--service-type=exec", "--unit=" + unit]
    launch += [f"--property={key}={value}" for key, value in properties.items()]
    launch += ["--", "/usr/bin/python3", "-I", str(Path(watcher.__file__)), str(os.getpid()), watcher.identity(os.getpid()), "--", *isolated]
    return launch, encoded(packet) + b"\n", properties


async def execute(packet, limits, check, receive, *, builder=command, prefix="ficc-data-"):
    unit = prefix + secrets.token_hex(16) + ".service"
    args, payload, properties = builder(packet, limits, unit)
    if len(payload) > MAX_FRAME:
        raise Failure("request_limit", "The source request exceeds 256 KiB.", 413)
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True, env=environment(), close_fds=True, bufsize=0)
    assert process.stdin and process.stdout
    stdin, stdout = process.stdin, process.stdout
    group, pidfd = None, os.pidfd_open(process.pid)
    reader = process.stdout.fileno()
    os.set_blocking(reader, False)
    os.set_blocking(process.stdin.fileno(), False)
    guard = None

    async def monitor():
        while True:
            check()
            await asyncio.sleep(0.2)

    async def exchange():
        nonlocal group
        for attempt in range(20):
            try:
                group = await enforcement(unit, properties=properties)
                break
            except Failure:
                if attempt == 19 or process.poll() is not None:
                    raise
                await asyncio.sleep(0.05)
        check()
        offset = 0
        while offset < len(payload):
            try:
                offset += os.write(stdin.fileno(), payload[offset:offset + 8192])
            except BlockingIOError:
                await ready(stdin.fileno(), writing=True)
        stdin.close()
        buffer = bytearray()
        receipt = False
        while True:
            try:
                chunk = os.read(reader, 65536)
            except BlockingIOError:
                await ready(reader)
                continue
            if not chunk:
                break
            buffer.extend(chunk)
            while b"\n" in buffer:
                line, _, tail = buffer.partition(b"\n")
                buffer = bytearray(tail)
                if len(line) > MAX_FRAME or receipt:
                    raise Failure("stream_protocol", "The source returned invalid stream framing.", 502)
                event = json.loads(line)
                if event.get("kind") == "error":
                    raise Failure(event["code"], event["message"], 409)
                check()
                await receive(event)
                receipt = event.get("kind") == "receipt"
                # A continuously readable pipe and synchronous receiver must
                # still let API cancellation, policy and lease maintenance run.
                await asyncio.sleep(0)
            if len(buffer) > MAX_FRAME:
                raise Failure("stream_protocol", "The source stream frame exceeds its limit.", 502)
        if buffer or not receipt:
            raise Failure("source_interrupted", "The source worker ended without a complete receipt.", 502)
        await ready(pidfd)
        if process.wait() != 0:
            raise Failure("source_failed", "The source worker failed after its receipt.", 502)

    task = asyncio.create_task(exchange())
    guard = asyncio.create_task(monitor())
    try:
        async with asyncio.timeout(limits["seconds"]):
            done, _ = await asyncio.wait((task, guard), return_when=asyncio.FIRST_COMPLETED)
            if guard in done:
                await guard
            await task
    finally:
        async def cleanup():
            for child in (task, guard):
                child.cancel()
            await asyncio.gather(task, guard, return_exceptions=True)
            try:
                await stop_service(unit, group)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await ready(pidfd)
                process.wait()
                stdin.close()
                stdout.close()
                os.close(pidfd)
        await finish_cleanup(cleanup())
