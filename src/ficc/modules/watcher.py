# SPDX-License-Identifier: Apache-2.0
"""Stop the isolated child when its controller identity exits.

Inputs are a controller PID, start identity and fixed sandbox command. Standard
streams carry the module protocol. Exit codes preserve child success or failure.
"""

import os
import select
import signal
import subprocess
import sys
from pathlib import Path


def identity(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19].decode("ascii")


def main() -> int:
    if len(sys.argv) < 5 or sys.argv[3] != "--":
        return 125
    owner_fd, child_fd, child = None, None, None
    try:
        owner = int(sys.argv[1])
        owner_fd = os.pidfd_open(owner)
        if identity(owner) != sys.argv[2]:
            return 125
        child = subprocess.Popen(sys.argv[4:], close_fds=True, start_new_session=True)
        child_fd = os.pidfd_open(child.pid)
        ready, _, _ = select.select([owner_fd, child_fd], [], [])
        if owner_fd in ready:
            return 125
        # Kill the owned group before reaping its leader, even after normal exit.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return child.wait()
    except (OSError, ValueError, IndexError):
        return 125
    finally:
        if child is not None and child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        for fd in (owner_fd, child_fd):
            if fd is not None:
                os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
