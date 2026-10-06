# SPDX-License-Identifier: Apache-2.0
"""Validate local service settings and private state paths."""

import logging
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .contributor_settings import ContributorSettings
from .contributor_settings import configuration as contributor_configuration
from .native_runtime import discover
from .remote_settings import RemoteSettings
from .remote_settings import configuration as remote_configuration
from .windows_runtime import discover as discover_windows

PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
SCOPES = {"nodes:read", "nodes:write", "resources:read", "observations:read", "observations:resources",
          "tokens:manage", "identities:manage", "policies:manage", "audit:read",
          "jobs:read", "jobs:execute", "jobs:cancel", "jobs:logs",
          "files:read", "files:write", "files:mode", "files:delete",
          "data:read", "data:export", "data:write", "data:manage",
          "terminals:read", "terminals:execute", "terminals:stop",
          "agents:read", "agents:execute", "agents:stop", "bus:read", "bus:send",
          "workspaces:read", "workspaces:write", "modules:read", "modules:manage",
          "modules:execute", "audio:playback", "vm:read", "vm:power", "vm:console", "providers:write",
          "container:read", "container:logs", "container:power",
          "admin:read", "admin:logs", "admin:services", "admin:power", "contributors:read", "contributors:manage"}
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
    viewer_runtime: Path | None = None
    viewer_runtime_error: str | None = field(default=None, init=False)
    windows_runtime: Path | None = None
    windows_runtime_error: str | None = field(default=None, init=False)
    remote: RemoteSettings | None = field(default=None, init=False, repr=False)
    contributors: ContributorSettings | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.state_dir = Path(self.state_dir).absolute()
        self.remote = remote_configuration(self.state_dir)
        self.contributors = contributor_configuration(self.state_dir)
        if self.contributors and (self.remote is None or self.contributors.origin == self.remote.origin
                                  or self.contributors.secret == self.remote.secret):
            raise ValueError("Contributor mode requires separate HTTPS endpoints and gateway credentials.")
        if self.viewer_runtime is not None:
            self.viewer_runtime = discover(Path(self.viewer_runtime))
        else:
            try:
                self.viewer_runtime = discover()
            except (OSError, ValueError):
                self.viewer_runtime_error = "The installed display runtime is invalid or incompatible. Install a verified runtime for this host."
                logging.getLogger(__name__).warning(self.viewer_runtime_error)
        if self.windows_runtime is not None:
            self.windows_runtime = discover_windows(Path(self.windows_runtime))
        else:
            try:
                self.windows_runtime = discover_windows()
            except (OSError, ValueError):
                self.windows_runtime_error = "The installed Windows transport is invalid or incompatible. Install a verified runtime for this host."
                logging.getLogger(__name__).warning(self.windows_runtime_error)
        if not 1024 <= self.port <= 65535:
            raise ValueError("Port must be between 1024 and 65535.")
        if len(self.profiles) > MAX_NODES or any(not PROFILE.fullmatch(p) for p in self.profiles):
            raise ValueError("SSH profile names are invalid.")
        if self.poll_interval < 1 or self.stale_after < self.poll_interval:
            raise ValueError("Polling intervals are invalid.")

    @property
    def origin(self) -> str:
        return self.remote.origin if self.remote is not None else f"http://127.0.0.1:{self.port}"

    @property
    def socket_path(self) -> Path:
        return self.state_dir / "control.sock"
