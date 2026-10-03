# SPDX-License-Identifier: Apache-2.0
"""Build a fixed Linux sandbox and check its kernel resource controls."""

import errno
import os
import re
import stat
from pathlib import Path

from ficc.modules import watcher

MEMORY_BYTES = 512 * 1024 * 1024
MAX_TASKS = 64
CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_ROOT = Path("/proc")
PROPERTIES = {
    "MemoryMax": str(MEMORY_BYTES), "MemorySwapMax": "0", "TasksMax": str(MAX_TASKS),
    "CPUQuota": "100%", "TimeoutStopSec": "1", "KillMode": "control-group",
    "SendSIGKILL": "yes", "NoNewPrivileges": "yes", "UMask": "0077",
    "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
    "OOMPolicy": "kill", "SystemCallArchitectures": "native", "LimitFSIZE": "16777216",
    "RestrictAddressFamilies": "AF_UNIX AF_NETLINK",
    "SystemCallFilter": "~@clock @module @raw-io @reboot @swap @obsolete @keyring",
}


def command(source: Path, run: Path, unit: str, arguments: list[str], finite: bool) -> list[str]:
    for executable in ("bwrap", "systemd-run", "systemctl", "python3"):
        if not os.access("/usr/bin/" + executable, os.X_OK):
            raise ValueError("The policy sandbox tools are unavailable.")
    isolated = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session",
                "--cap-drop", "ALL", "--clearenv", "--ro-bind", str(run / "opa"), "/opa",
                "--ro-bind", str(source), "/policy", "--ro-bind", str(run / "capabilities.json"),
                "/capabilities.json", "--bind", str(run / "work"), "/run",
                "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chdir", "/policy",
                "--hostname", "ficc-policy", "--setenv", "GOMEMLIMIT", "256MiB",
                "--setenv", "GOMAXPROCS", "2"]
    if not finite:
        isolated += ["--ro-bind", str(run / "work" / "policy.tar.gz"), "/bundle.tar.gz"]
    isolated += ["--", "/opa", *arguments]
    properties = {**PROPERTIES, **({"RuntimeMaxSec": "15"} if finite else {})}
    launch = ["/usr/bin/systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect",
              "--service-type=exec", "--unit=" + unit]
    launch += [f"--property={key}={value}" for key, value in properties.items()]
    return launch + ["--", "/usr/bin/python3", "-I", str(Path(__file__).with_name("admit.py")),
                     str(Path(watcher.__file__).resolve()), str(os.getpid()),
                     watcher.identity(os.getpid()), "--", *isolated]


def group_path(values: dict[str, str]) -> Path:
    group = values.get("ControlGroup", "")
    if not re.fullmatch(r"/[a-zA-Z0-9_.@:/-]+", group) or ".." in group.split("/"):
        raise ValueError("The policy control group is unavailable.")
    return CGROUP_ROOT / group.lstrip("/")


def read(directory: int, name: str, limit: int = 4096) -> str:
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=directory)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("The kernel control file is invalid.")
        data = bytearray()
        while chunk := os.read(fd, limit + 1 - len(data)):
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError("The kernel control file exceeds its limit.")
        return data.decode("ascii").strip()
    finally:
        os.close(fd)


def limits(directory: int) -> None:
    values = {name: read(directory, name) for name in
              ("memory.max", "memory.swap.max", "pids.max", "cpu.max")}
    quota, period = values["cpu.max"].split()
    if (values["memory.max"] != str(MEMORY_BYTES) or values["memory.swap.max"] != "0"
            or values["pids.max"] != str(MAX_TASKS) or not 0 < int(quota) <= int(period)):
        raise ValueError("The kernel policy limits differ.")


def enforcement(values: dict[str, str]) -> Path:
    for key in ("MemoryMax", "MemorySwapMax", "TasksMax", "NoNewPrivileges", "KillMode"):
        if values.get(key) != PROPERTIES[key]:
            raise ValueError("The policy resource controls are not active.")
    group = group_path(values)
    try:
        directory = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            limits(directory)
        finally:
            os.close(directory)
    except (OSError, ValueError):
        raise ValueError("The kernel policy controls are unavailable.") from None
    return group


class Controls:
    """Bind admitted kernel objects and check their current process limits."""

    def __init__(self, group: Path, main_pid: str):
        self.group = group
        self.directory = -1
        self.main = -1
        try:
            if not re.fullmatch(r"[1-9][0-9]{0,9}", main_pid):
                raise ValueError("The policy main process is unavailable.")
            self.pid = int(main_pid)
            self.membership = "0::/" + str(group.relative_to(CGROUP_ROOT))
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            self.directory = os.open(group, flags)
            value = os.fstat(self.directory)
            self.identity = (value.st_dev, value.st_ino)
            self.main = os.open(PROC_ROOT / main_pid, flags)
            self.check()
        except BaseException:
            self.close()
            raise

    def same_path(self) -> bool:
        try:
            value = self.group.lstat()
            return stat.S_ISDIR(value.st_mode) and (value.st_dev, value.st_ino) == self.identity
        except FileNotFoundError:
            return False

    def member(self, directory: int, pid: int, members: set[int]) -> None:
        fields = dict(line.split(":", 1) for line in read(directory, "status", 16384).splitlines()
                      if ":" in line)
        state = fields.get("State", "").strip().split()
        if (fields.get("NoNewPrivs", "").strip() != "1"
                or fields.get("Pid", "").strip() != str(pid)
                or not state or state[0] not in ("R", "S", "D", "T", "t", "I", "P")):
            raise ValueError("The policy process controls are unavailable.")
        groups = [line for line in read(directory, "cgroup").splitlines() if line.startswith("0:")]
        if groups != [self.membership]:
            raise ValueError("The policy process control group changed.")
        children = read(directory, f"task/{pid}/children").split()
        if (len(children) > MAX_TASKS or any(not child.isdecimal() for child in children)
                or not {int(child) for child in children} <= members):
            raise ValueError("The policy child process left its control group.")

    def check(self) -> None:
        try:
            if not self.same_path():
                raise ValueError("The policy control group changed.")
            limits(self.directory)
            counts = dict(line.split() for line in read(self.directory, "cgroup.stat").splitlines())
            if (read(self.directory, "cgroup.type") != "domain"
                    or counts.get("nr_descendants") != "0"):
                raise ValueError("The policy control group structure changed.")
            identifiers = read(self.directory, "cgroup.procs").split()
            if (not 1 <= len(identifiers) <= MAX_TASKS
                    or any(not re.fullmatch(r"[1-9][0-9]{0,9}", pid) for pid in identifiers)):
                raise ValueError("The policy process list is invalid.")
            members = {int(pid) for pid in identifiers}
            if self.pid not in members:
                raise ValueError("The policy main process is unavailable.")
            self.member(self.main, self.pid, members)
            for pid in members - {self.pid}:
                directory = os.open(PROC_ROOT / str(pid), os.O_RDONLY | os.O_DIRECTORY
                                    | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    self.member(directory, pid, members)
                finally:
                    os.close(directory)
            if not self.same_path():
                raise ValueError("The policy control group changed.")
        except (OSError, ValueError):
            raise ValueError("The current kernel policy controls are unavailable.") from None

    def empty(self) -> bool:
        try:
            return "populated 0" in read(self.directory, "cgroup.events").splitlines()
        except OSError as exc:
            if (exc.errno in (errno.ENOENT, errno.ENODEV)
                    and os.readlink(f"/proc/self/fd/{self.directory}").endswith(" (deleted)")):
                return True
            raise

    def kill(self) -> None:
        fd = os.open("cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                     dir_fd=self.directory)
        try:
            os.write(fd, b"1")
        finally:
            os.close(fd)

    def close(self) -> None:
        for name in ("main", "directory"):
            fd = getattr(self, name)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)


def empty(group: Path) -> bool:
    try:
        return "populated 0" in (group / "cgroup.events").read_text().splitlines()
    except FileNotFoundError:
        return True
