# SPDX-License-Identifier: Apache-2.0
"""Hold exclusive controller-state ownership before any database access."""

import fcntl
import os
import stat
from pathlib import Path

from .settings import private_directory


class StateLock:
    def __init__(self, state_dir: Path):
        self.fd: int | None = None
        private_directory(state_dir)
        fd = os.open(state_dir / "service.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise ValueError("The state lock must be a private regular file.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("A service or maintenance command already uses this state directory.") from None
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()
