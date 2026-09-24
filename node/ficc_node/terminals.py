# SPDX-License-Identifier: Apache-2.0
"""Create and attach exact tmux sessions in a private controller namespace."""

import fcntl
import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

from .job_state import boot_id, directory, read, write

ID = re.compile(r"[0-9a-f]{32}\Z")


def identity(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError("Invalid terminal identity.")
    return value


def base(controller):
    identity(controller)
    home = Path.home()
    for part in (home / ".local", home / ".local/state", home / ".local/state/ficc"):
        if part.is_symlink():
            raise ValueError("Terminal state cannot use symbolic links.")
    return directory(directory(home / ".local/state/ficc/terminals") / controller)


def command(controller, *args):
    return ["tmux", "-f", "/dev/null", "-L", "ficc-" + identity(controller), *args]


def call(controller, *args):
    return subprocess.run(command(controller, *args), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=5, check=False).returncode


@contextmanager
def locked(controller):
    folder = base(controller)
    fd = os.open(folder / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield folder
    finally:
        os.close(fd)


def dispatch(request):
    if set(request) - {"version", "action", "controller_id", "terminal_id", "cols", "rows"}:
        raise ValueError("Invalid terminal request fields.")
    controller, terminal = identity(request["controller_id"]), identity(request["terminal_id"])
    action = request["action"]
    if action not in ("terminal.create", "terminal.status", "terminal.stop"):
        raise ValueError("Invalid terminal action.")
    if not shutil.which("tmux"):
        raise ValueError("Tmux is unavailable on this machine.")
    with locked(controller) as folder:
        path = folder / (terminal + ".json")
        value = read(path) if path.exists() else None
        present = call(controller, "has-session", "-t", "=" + terminal) == 0
        if action == "terminal.create":
            cols, rows = request.get("cols"), request.get("rows")
            if type(cols) is not int or type(rows) is not int or not (2 <= cols <= 300 and 2 <= rows <= 120):
                raise ValueError("Invalid terminal dimensions.")
            if value is None:
                if present or sum(1 for _ in folder.glob("*.json")) >= 512:
                    raise ValueError("The terminal namespace is full or has an unrecorded session.")
                value = {"id": terminal, "boot_id": boot_id(), "state": "creating",
                         "cols": cols, "rows": rows}
                write(path, value)
                # The intent remains if creation has an uncertain outcome; never recreate it.
                result = call(controller, "new-session", "-d", "-s", terminal,
                              "-x", str(cols), "-y", str(rows))
                present = call(controller, "has-session", "-t", "=" + terminal) == 0
                if result or not present:
                    value["state"] = "unknown"
                else:
                    value["state"] = "detached"
                write(path, value)
            elif (value["cols"], value["rows"]) != (cols, rows):
                raise ValueError("The terminal request conflicts with its saved identity.")
        if value is None:
            if present:
                raise ValueError("An unrecorded terminal session requires manual recovery.")
            return {"state": "missing"}
        if action == "terminal.stop":
            if present:
                if call(controller, "kill-session", "-t", "=" + terminal):
                    raise ValueError("The terminal stop could not be confirmed.")
            value["state"] = "stopped"
            write(path, value)
            return {"state": "stopped"}
        if value["state"] == "stopped":
            return {"state": "stopped"}
        return {"state": "detached" if present else "missing"}


def attach(controller, terminal):
    identity(controller)
    identity(terminal)
    with locked(controller) as folder:
        value = read(folder / (terminal + ".json"))
        if value["state"] == "stopped" or call(controller, "has-session", "-t", "=" + terminal):
            raise ValueError("The terminal session is no longer available.")
    # attach-session never creates a replacement after a missing or stopped session.
    os.execvp("tmux", command(controller, "attach-session", "-t", "=" + terminal))
