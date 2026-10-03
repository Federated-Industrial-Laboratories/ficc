# SPDX-License-Identifier: Apache-2.0
"""Supervise bounded process streams and stop the complete owned service."""

import os
import secrets
import signal
import subprocess
import time
from pathlib import Path

from ficc.modules.sandbox import environment

from . import isolation

MAX_OUTPUT = 64 * 1024
MANAGEMENT_SECONDS = 3.0
START_SECONDS = 5.0
COMPILE_SECONDS = 10.0


class Output:
    def __init__(self, process: subprocess.Popen):
        self.pipes = [process.stdout, process.stderr]
        self.data = [bytearray(), bytearray()]
        for pipe in self.pipes:
            assert pipe is not None
            os.set_blocking(pipe.fileno(), False)

    def drain(self) -> None:
        for index, pipe in enumerate(self.pipes):
            if pipe is None or pipe.closed:
                continue
            while True:
                try:
                    chunk = os.read(pipe.fileno(), 8192)
                except BlockingIOError:
                    break
                if not chunk:
                    pipe.close()
                    break
                if len(self.data[index]) + len(chunk) > MAX_OUTPUT:
                    raise ValueError("The policy process output exceeds its limit.")
                self.data[index].extend(chunk)

    def close(self) -> None:
        for pipe in self.pipes:
            if pipe is not None:
                pipe.close()


def reap(process: subprocess.Popen) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        raise ValueError("The policy process stop could not be confirmed.") from None


def management(*arguments: str) -> tuple[int, bytes]:
    process = subprocess.Popen(["/usr/bin/systemctl", "--user", *arguments],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment(), close_fds=True,
                               start_new_session=True)
    output = Output(process)
    deadline = time.monotonic() + MANAGEMENT_SECONDS
    try:
        while True:
            output.drain()
            code = process.poll()
            if code is not None:
                output.drain()
                return code, bytes(output.data[0])
            if time.monotonic() >= deadline:
                raise ValueError("The policy service manager did not respond.")
            time.sleep(0.01)
    finally:
        try:
            reap(process)
        finally:
            output.close()


def properties(unit: str) -> dict[str, str]:
    names = ("LoadState", "ActiveState", "MainPID", "ControlGroup", "MemoryMax",
             "MemorySwapMax", "TasksMax", "NoNewPrivileges", "KillMode")
    _, data = management("show", unit, *["--property=" + name for name in names])
    return dict(line.split("=", 1) for line in data.decode("utf-8").splitlines() if "=" in line)


class Service:
    def __init__(self, source: Path, run: Path, arguments: list[str], *, finite: bool):
        self.unit = "ficc-policy-" + secrets.token_hex(16) + ".service"
        self.group: Path | None = None
        self.controls: isolation.Controls | None = None
        self.closed = False
        args = isolation.command(source, run, self.unit, arguments, finite)
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=environment(), close_fds=True,
                                        start_new_session=True, bufsize=0)
        self.output = Output(self.process)

    def admit(self) -> None:
        deadline = time.monotonic() + START_SECONDS
        while time.monotonic() < deadline:
            self.healthy()
            values = properties(self.unit)
            if values.get("ControlGroup"):
                self.group = isolation.group_path(values)
                isolation.enforcement(values)
                self.controls = isolation.Controls(self.group, values.get("MainPID", ""))
                assert self.process.stdin is not None
                self.process.stdin.write(b"1")
                self.process.stdin.close()
                return
            time.sleep(0.02)
        raise ValueError("The policy resource controls did not start.")

    def healthy(self) -> None:
        self.output.drain()
        if self.closed or self.process.poll() is not None:
            raise ValueError("The policy evaluator is unavailable.")

    def check(self) -> None:
        self.healthy()
        if self.controls is None:
            raise ValueError("The policy controls have not been admitted.")
        self.controls.check()

    def wait(self) -> None:
        deadline = time.monotonic() + COMPILE_SECONDS
        while True:
            self.output.drain()
            code = self.process.poll()
            if code is not None:
                self.output.drain()
                if code:
                    raise ValueError("The policy source could not be compiled.")
                return
            if time.monotonic() >= deadline:
                raise ValueError("The policy compilation exceeded its time limit.")
            time.sleep(0.02)

    def close(self) -> None:
        if self.closed:
            return
        confirmed = False
        try:
            try:
                code, _ = management("stop", self.unit)
                if code:
                    raise ValueError("The policy service manager could not stop the service.")
            except (ValueError, OSError):
                try:
                    management("kill", "--kill-whom=all", "--signal=KILL", self.unit)
                except (ValueError, OSError):
                    pass
            if self.group is None:
                values = properties(self.unit)
                if values.get("ControlGroup"):
                    self.group = isolation.group_path(values)
                else:
                    confirmed = (values.get("LoadState") == "not-found" or
                                 (values.get("ActiveState") in ("inactive", "failed")
                                  and values.get("MainPID") == "0"))
            if self.group is not None:
                group = self.group
                stopped = (self.controls.empty if self.controls is not None
                           else lambda: isolation.empty(group))
                if not stopped():
                    try:
                        if self.controls is not None:
                            self.controls.kill()
                        else:
                            (self.group / "cgroup.kill").write_text("1")
                    except OSError:
                        pass
                deadline = time.monotonic() + 3
                while not stopped() and time.monotonic() < deadline:
                    time.sleep(0.02)
                confirmed = stopped()
        finally:
            try:
                reap(self.process)
            finally:
                if self.process.stdin is not None:
                    self.process.stdin.close()
                self.output.close()
        if not confirmed:
            raise ValueError("The policy service stop could not be confirmed.")
        if self.controls is not None:
            self.controls.close()
        self.closed = True


def compile_source(source: Path, run: Path) -> None:
    for arguments in (
        ["check", "--strict", "--capabilities", "/capabilities.json", "/policy"],
        ["build", "--capabilities", "/capabilities.json", "--output", "/run/policy.tar.gz", "/policy"],
    ):
        service = Service(source, run, arguments, finite=True)
        try:
            service.admit()
            service.wait()
        finally:
            service.close()
