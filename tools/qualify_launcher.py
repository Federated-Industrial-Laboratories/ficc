#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Check a desktop service with separate state and remove only its generated files.
# Inputs: installed command and optional report path. Exit: zero when checks pass.
"""Exercise generated service startup, isolation, restart and cleanup on a desktop."""

import argparse
import json
import os
import socket
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path


def qualify(command: Path, *, require_sandbox: bool = False) -> dict:
    name = "ficc-check-" + uuid.uuid4().hex
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    data_root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    unit = config_root / "systemd/user" / (name + ".service")
    desktop = data_root / "applications" / (name + ".desktop")
    if any(path.exists() or path.is_symlink() for path in (unit, desktop)):
        raise ValueError("The qualification name is already in use.")
    checks = []
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"PYTHONPATH", "PYTHONHOME", "APPDIR", "APPIMAGE"}}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"

    def run(*arguments):
        return subprocess.check_output(arguments, text=True, env=environment, timeout=60).strip()

    def cli(*arguments):
        return json.loads(run(str(command), *arguments))

    def check(label, condition):
        if not condition:
            raise ValueError("Launcher check failed: " + label)
        checks.append(label)

    def pid():
        return int(run("systemctl", "--user", "show", name, "--property=MainPID", "--value"))

    with tempfile.TemporaryDirectory(prefix="ficc-launcher-check-") as temporary:
        path = Path(temporary)
        config, state = path / "launcher.json", path / "state"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        install = ("install-launcher", "--launcher-config", str(config), "--name", name,
                   "--state-dir", str(state), "--port", str(port), "--demo")
        generated = {}
        try:
            result = cli(*install)
            for target in (unit, desktop):
                generated[target] = target.read_bytes()
            check("on-demand installation", result["autostart"] is False)
            check("installation does not start", pid() == 0)
            check("authenticated startup", cli("start", "--launcher-config", str(config))["ready"])
            first_pid = pid()
            check("service process", first_pid > 0)
            check("saved configuration", json.loads(config.read_text())["state_dir"] == str(state))
            check("ready status", cli("status", "--launcher-config", str(config))["ready"])
            status = dict(line.split(":", 1) for line in
                          Path(f"/proc/{first_pid}/status").read_text().splitlines() if ":" in line)
            check("no new privileges", status["NoNewPrivs"].strip() == "1")
            values = dict(item.split(b"=", 1) for item in
                          Path(f"/proc/{first_pid}/environ").read_bytes().split(b"\0") if b"=" in item)
            scratch = Path(os.fsdecode(values[b"TMPDIR"]))
            check("managed temporary path", values[b"TMPDIR"] == values[b"RUNTIME_DIRECTORY"])
            info = scratch.lstat()
            check("private temporary directory", stat.S_ISDIR(info.st_mode)
                  and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
            check("private controller state", stat.S_IMODE(state.stat().st_mode) == 0o700)
            sandbox = cli("module-sandbox", "--state-dir", str(state))
            if require_sandbox:
                check("module sandbox enforcement", sandbox["available"] is True)
            check("repeated start ready", cli("start", "--launcher-config", str(config))["ready"])
            check("repeated start retains process", pid() == first_pid)
            before = {item["id"] for item in cli("nodes", "--state-dir", str(state))["nodes"]}
            check("demo inventory", bool(before))
            check("explicit stop", cli("stop", "--launcher-config", str(config))["stopped"])
            check("stopped process", pid() == 0)
            check("temporary cleanup", not scratch.exists())
            check("control socket cleanup", not (state / "control.sock").exists())
            original = generated[unit]
            previous = original.replace(("RuntimeDirectory=" + name + "\nRuntimeDirectoryMode=0700\n"
                                         "Environment=TMPDIR=%t/" + name + "\n").encode(), b"PrivateTmp=true\n")
            check("legacy service fixture", previous != original)
            unit.write_bytes(previous)
            generated[unit] = previous
            run("systemctl", "--user", "daemon-reload")
            check("legacy upgrade ready", cli("start", "--launcher-config", str(config))["ready"])
            check("legacy service repaired", unit.read_bytes() == original)
            generated[unit] = original
            cli("stop", "--launcher-config", str(config))
            cli(*install)
            check("restart after reinstall", cli("start", "--launcher-config", str(config))["ready"])
            after = {item["id"] for item in cli("nodes", "--state-dir", str(state))["nodes"]}
            check("retained inventory", before == after)
        finally:
            # A failed install can leave a generated unit before saving its configuration.
            marker = ("# Generated by FICC launcher.\n# Configuration: " + str(config) + "\n").encode()
            if unit.exists() and not unit.is_symlink() and unit.read_bytes().startswith(marker):
                run("systemctl", "--user", "stop", name)
            for target in (unit, desktop):
                if not target.exists() and not target.is_symlink():
                    continue
                expected = generated.get(target)
                if (target.is_symlink() or not target.read_bytes().startswith(marker)
                        or (expected is not None and target.read_bytes() != expected)):
                    raise ValueError("A qualification file changed. Inspect before removal: " + str(target))
                target.unlink()
            run("systemctl", "--user", "daemon-reload")
    return {"passed": len(checks), "failed": 0, "checks": checks, "sandbox": sandbox,
            "unit_removed": not unit.exists(), "desktop_removed": not desktop.exists()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", type=Path, required=True)
    parser.add_argument("--require-sandbox", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    value = json.dumps(qualify(args.command.absolute(), require_sandbox=args.require_sandbox), indent=2) + "\n"
    if args.report:
        args.report.write_text(value)
    print(value, end="")


if __name__ == "__main__":
    main()
