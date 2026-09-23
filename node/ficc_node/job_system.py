# SPDX-License-Identifier: Apache-2.0
"""Inspect systemd capabilities and verify effective cgroup limits."""

import os
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path


def command(argv, timeout=8):
    env = dict(os.environ)
    runtime = Path(f"/run/user/{os.getuid()}")
    if runtime.is_dir() and runtime.stat().st_uid == os.getuid():
        env.setdefault("XDG_RUNTIME_DIR", str(runtime))
        env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime}/bus")
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, env=env, check=False)
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise ValueError("System manager response exceeds the limit.")
    return result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace")


def capability():
    result: dict[str, bool | str] = {"jobs": False, "logout_persistent": False}
    try:
        code, output, _ = command(["systemctl", "--user", "show", "--property=ControlGroup", "--value"])
        if code or not output.strip().startswith("/"):
            raise ValueError("The systemd user manager is unavailable.")
        group = Path("/sys/fs/cgroup") / output.strip().lstrip("/")
        controllers = (group / "cgroup.controllers").read_text().split()
        if not {"cpu", "memory", "pids"}.issubset(controllers):
            raise ValueError("The user manager lacks required cgroup controllers.")
        code, version, _ = command(["systemd-run", "--version"])
        if code or int(version.split()[1]) < 255:
            raise ValueError("Managed jobs require systemd 255 or newer.")
        code, linger, _ = command(["loginctl", "show-user", str(os.getuid()), "-p", "Linger", "--value"])
        result.update(jobs=True, logout_persistent=code == 0 and linger.strip() == "yes")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result["job_error"] = str(exc)[:240]
    return result


def properties(unit):
    keys = ("Id", "Description", "LoadState", "ActiveState", "SubState", "Result",
            "ExecMainCode", "ExecMainStatus", "ControlGroup")
    code, output, _ = command(["systemctl", "--user", "show", unit, "--property=" + ",".join(keys)])
    values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if code and values.get("LoadState") != "not-found":
        raise ValueError("The systemd job state is unavailable.")
    return values


def current_group(unit=None):
    line = next(line for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::"))
    root = Path("/sys/fs/cgroup")
    group = root / line[3:].lstrip("/")
    if ".." in group.parts:
        raise ValueError("Invalid cgroup path.")
    if unit is not None and group.name != unit:
        raise ValueError("The runner is outside its recorded service cgroup.")
    return group


def settle(unit):
    group = current_group(unit)
    deadline = time.monotonic() + 3
    while True:
        members: list[Path] = []
        for current, directories, _ in os.walk(group):
            if len(members) + len(directories) > 256:
                return False
            members.append(Path(current))
        children = [(int(pid), member) for member in members
                    for pid in (member / "cgroup.procs").read_text().split() if int(pid) != os.getpid()]
        if not children:
            return True
        for pid, member in children:
            with suppress(ProcessLookupError, FileNotFoundError):
                fd = os.pidfd_open(pid)
                try:
                    membership = Path(f"/proc/{pid}/cgroup").read_text()
                    expected = "0::/" + member.relative_to("/sys/fs/cgroup").as_posix()
                    if expected in membership.splitlines():
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                finally:
                    os.close(fd)
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def verify(limits, unit=None):
    group = current_group(unit)
    root = Path("/sys/fs/cgroup")
    if (group / "memory.oom.group").read_text().strip() != "1":
        raise ValueError("The service does not enforce group OOM termination.")
    files = {"memory_high_bytes": "memory.high", "memory_max_bytes": "memory.max",
             "memory_swap_max_bytes": "memory.swap.max", "tasks_max": "pids.max"}
    effective: dict[str, int | float] = {}
    for name, filename in files.items():
        raw = (group / filename).read_text().strip()
        if raw == "max" or int(raw) > limits[name]:
            raise ValueError(f"Required cgroup limit is unavailable: {name}.")
        values = [int(raw)]
        for parent in group.parents:
            if parent == root.parent:
                break
            file = parent / filename
            if file.exists():
                value = file.read_text().strip()
                if value != "max":
                    values.append(int(value))
        effective[name] = min(values)
    quota, period = (group / "cpu.max").read_text().split()
    if quota == "max" or int(quota) * 100 > limits["cpu_percent"] * int(period):
        raise ValueError("Required CPU quota is unavailable.")
    cpu = int(quota) * 100 / int(period)
    for parent in group.parents:
        if parent == root.parent:
            break
        file = parent / "cpu.max"
        if file.exists():
            quota, period = file.read_text().split()
            if quota != "max":
                cpu = min(cpu, int(quota) * 100 / int(period))
    effective["cpu_percent"] = cpu
    effective["runtime_seconds"] = limits["runtime_seconds"]
    return effective


def start(request, runner):
    limits = request["job"]["limits"]
    properties = {"Type": "exec", "RemainAfterExit": "yes", "KillMode": "control-group",
                  "TimeoutStopSec": "10s", "NoNewPrivileges": "yes", "UMask": "0077",
                  "StandardOutput": "null", "StandardError": "null", "OOMPolicy": "kill",
                  "RuntimeMaxSec": str(limits["runtime_seconds"]),
                  "CPUQuota": f'{limits["cpu_percent"]}%', "MemoryHigh": str(limits["memory_high_bytes"]),
                  "MemoryMax": str(limits["memory_max_bytes"]), "MemorySwapMax": str(limits["memory_swap_max_bytes"]),
                  "TasksMax": str(limits["tasks_max"])}
    argv = ["systemd-run", "--user", "--quiet", "--expand-environment=no", "--unit=" + request["unit"],
            "--description=" + request["description"]]
    argv += [f"--property={key}={value}" for key, value in properties.items()]
    argv += ["--", "/usr/bin/python3", str(runner), "--run-job", request["job_id"]]
    code, _, error = command(argv)
    if code:
        detail = " ".join(error.split())[:180]
        raise ValueError("The system manager did not acknowledge the job launch: " + (detail or "no diagnostic"))
