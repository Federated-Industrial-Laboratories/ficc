# SPDX-License-Identifier: Apache-2.0
"""Validate local service settings and private state paths."""

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
SCOPES = {"nodes:read", "nodes:write", "resources:read", "tokens:manage", "audit:read"}
MAX_NODES = 64
MAX_MESSAGE = 1024 * 1024


def default_state_dir() -> Path:
    root = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    return root / "ficc"


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("State directory must be owned by the current account.")
    if info.st_mode & 0o077:
        raise ValueError("State directory must have mode 0700.")


@dataclass
class Settings:
    state_dir: Path = field(default_factory=default_state_dir)
    port: int = 8170
    profiles: tuple[str, ...] = ()
    demo: bool = False
    ssh_config: Path | None = None
    poll_interval: float = 5.0
    stale_after: float = 15.0
    control: bool = True

    def __post_init__(self) -> None:
        self.state_dir = Path(self.state_dir).absolute()
        if not 1024 <= self.port <= 65535:
            raise ValueError("Port must be between 1024 and 65535.")
        if len(self.profiles) > MAX_NODES or any(not PROFILE.fullmatch(p) for p in self.profiles):
            raise ValueError("SSH profile names are invalid.")
        if self.poll_interval < 1 or self.stale_after < self.poll_interval:
            raise ValueError("Polling intervals are invalid.")

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def socket_path(self) -> Path:
        return self.state_dir / "control.sock"
