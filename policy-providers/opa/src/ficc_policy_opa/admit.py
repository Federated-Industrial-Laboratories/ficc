# SPDX-License-Identifier: Apache-2.0
"""Wait for checked resource controls before starting the fixed child watcher.

Inputs are the watcher path, controller identity and sandbox command. Standard
input admits the child. Exit code 125 indicates missing admission or owner.
"""

import os
import select
import sys
from pathlib import Path


def main() -> int:
    owner_fd = None
    try:
        if len(sys.argv) < 7 or sys.argv[4] != "--":
            return 125
        owner = int(sys.argv[2])
        owner_fd = os.pidfd_open(owner)
        identity = Path(f"/proc/{owner}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19]
        if identity.decode("ascii") != sys.argv[3]:
            return 125
        ready, _, _ = select.select([owner_fd, 0], [], [], 10)
        if owner_fd in ready or 0 not in ready or os.read(0, 1) != b"1":
            return 125
        os.close(owner_fd)
        owner_fd = None
        os.execv("/usr/bin/python3", ["/usr/bin/python3", "-I", *sys.argv[1:]])
    except (OSError, ValueError, IndexError):
        return 125
    finally:
        if owner_fd is not None:
            os.close(owner_fd)
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
