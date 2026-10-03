# SPDX-License-Identifier: Apache-2.0
"""Build exact-file, no-network workers using the shared provider supervisor."""

import os
import re
import sys
from pathlib import Path

import ficc_node

from .data_sdk import encoded
from .errors import Failure
from .inspection_sdk import load
from .modules import watcher
from .modules.sandbox import PROPERTIES


def approved_assets(service, module, configuration):
    result = module.assets(configuration)
    if not isinstance(result, dict) or not 1 <= len(result) <= 16:
        raise Failure("scanner_assets", "The scanner asset manifest is invalid.", 409)
    private = service.settings.state_dir.resolve()
    values = {}
    for name, path in result.items():
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) or not isinstance(path, str):
            raise Failure("scanner_assets", "The scanner asset manifest is invalid.", 409)
        resolved = Path(path).resolve(strict=True)
        if (not Path(path).is_absolute() or private.is_relative_to(resolved) or resolved.is_relative_to(private)
                or resolved in {Path("/"), Path("/home"), Path("/etc"), Path("/var"), Path("/tmp"), Path("/run")}):
            raise Failure("scanner_assets", "Approve narrow scanner assets outside controller private state.", 403)
        if not os.access(resolved, os.R_OK | (os.X_OK if resolved.is_dir() else 0)):
            raise Failure("scanner_assets", "An approved scanner asset is unavailable.", 409)
        values[name] = str(resolved)
    return values


def command(packet, limits, unit):
    properties = {**PROPERTIES, "MemoryMax": str(limits["memory_bytes"]), "RuntimeMaxSec": str(limits["seconds"] + 2)}
    isolated = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"]
    module, _ = load(packet["provider"])
    packages = {Path(__file__).parents[1], Path(ficc_node.__file__).parents[1], Path(module.__file__).parents[1]}
    mounts = packages | {Path("/usr"), Path(sys.prefix).absolute()}
    for path in (Path("/lib"), Path("/lib64"), Path("/bin")):
        if path.exists():
            mounts.add(path)
    private = Path(packet["private_path"]).resolve()
    if any(private.is_relative_to(path.resolve()) or path.resolve().is_relative_to(private) for path in mounts):
        raise Failure("scanner_layout", "The runtime installation overlaps controller private state.", 409)
    for path in sorted(mounts, key=str):
        isolated += ["--ro-bind", str(path), str(path)]
    isolated += ["--proc", "/proc", "--dev", "/dev", "--size", str(limits["temp_bytes"]), "--tmpfs", "/tmp",
                 "--dir", "/work", "--chdir", "/work", "--dir", "/input", "--dir", "/scanner"]
    isolated += ["--ro-bind", packet["file_path"], "/input/file"]
    assets = {}
    for name, path in packet["assets"].items():
        assets[name] = "/scanner/" + name
        if Path(path).is_file():
            isolated += ["--dir", assets[name]]
            assets[name] += "/" + Path(path).name
        isolated += ["--ro-bind", path, assets[name]]
    for key, value in {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent", "TMPDIR": "/tmp",
                       "PYTHONPATH": ":".join(str(path) for path in sorted(packages, key=str)), "OMP_NUM_THREADS": "1"}.items():
        isolated += ["--setenv", key, value]
    isolated += ["--", sys.executable, "-m", "ficc.inspection_worker"]
    launch = ["/usr/bin/systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect", "--service-type=exec", "--unit=" + unit]
    launch += [f"--property={key}={value}" for key, value in properties.items()]
    launch += ["--", "/usr/bin/python3", "-I", str(Path(watcher.__file__)), str(os.getpid()), watcher.identity(os.getpid()), "--", *isolated]
    packet = {key: value for key, value in packet.items() if key not in {"file_path", "private_path"}}
    return launch, encoded({**packet, "assets": assets}) + b"\n", properties


async def execute(packet, limits, check, receive):
    from .source_runtime import execute as supervise
    await supervise(packet, limits, check, receive, builder=command, prefix="ficc-inspection-")
