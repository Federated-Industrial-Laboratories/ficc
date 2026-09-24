# SPDX-License-Identifier: Apache-2.0
"""Install and control the per-user service and authenticated desktop launcher."""

import fcntl
import os
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from urllib.parse import quote

import httpx

from .launcher_config import (
    MARKER,
    NAME,
    LaunchConfig,
    desktop_text,
    load,
    save,
    unit_text,
    write_file,
)
from .settings import private_directory


def systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(["systemctl", "--user", *arguments], capture_output=True,
                                text=True, timeout=25, check=False)
    except subprocess.TimeoutExpired:
        raise ValueError("The user service request timed out. Inspect systemctl --user status before retrying.") from None
    if check and result.returncode:
        raise ValueError("The user service request failed. Check systemctl --user status and journalctl --user.")
    return result


@contextmanager
def startup_lock(path: Path):
    private_directory(path.parent)
    fd = os.open(path.parent / "launcher.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + 35
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError("Another launcher is busy. Try again after it finishes.") from None
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


def verify_unit(config: LaunchConfig, path: Path) -> None:
    unit = Path(config.unit_path)
    if unit.is_symlink() or unit.read_text() != unit_text(config, path):
        raise ValueError("The installed service differs from this launcher configuration. Reinstall the launcher.")
    result = systemctl("show", config.unit, "--property=FragmentPath", "--value")
    if result.stdout.strip() != config.unit_path:
        raise ValueError("Another service uses this name. Select a different launcher name.")
    result = systemctl("show", config.unit, "--property=DropInPaths", "--value")
    if result.stdout.strip():
        raise ValueError("Service overrides are present. Remove the overrides or use a different launcher name.")


def install(args) -> dict:
    path = args.launcher_config.absolute()
    if not NAME.fullmatch(args.name):
        raise ValueError("The launcher name must be ficc or ficc- followed by letters, digits or hyphens.")
    executable = Path(sys.executable).absolute().parent / "ficc"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("Install FICC in a virtual environment before installing its launcher.")
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    data_root = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
    unit = config_root / "systemd/user" / (args.name + ".service")
    desktop = data_root / "applications" / (args.name + ".desktop")
    config = LaunchConfig(str(executable), str(args.state_dir.absolute()), str(unit.absolute()),
                          str(desktop.absolute()), args.port, tuple(args.profile),
                          str(args.ssh_config.absolute()) if args.ssh_config else None, args.demo)
    private_directory(Path(config.state_dir))
    with startup_lock(path):
        if path.exists() or path.is_symlink():
            old = load(path)
            if old.unit_path != config.unit_path or old.desktop_path != config.desktop_path:
                raise ValueError("Use a separate configuration file for a different launcher name.")
        for target in (unit, desktop):
            if target.exists() or target.is_symlink():
                expected = MARKER + "# Configuration: " + str(path) + "\n"
                if target.is_symlink() or not target.read_text().startswith(expected):
                    raise ValueError("An existing startup file is not managed by FICC. Choose another name.")
        if unit.exists() and systemctl("is-active", config.unit, check=False).returncode == 0:
            raise ValueError("Stop the service before changing its launcher settings.")
        write_file(unit, unit_text(config, path))
        write_file(desktop, desktop_text(config, path), 0o644)
        save(path, config)
        systemctl("daemon-reload")
        verify_unit(config, path)
        if args.autostart:
            systemctl("enable", config.unit)
    return {"configuration": str(path), "desktop_entry": str(desktop), "unit": config.unit,
            "autostart": systemctl("is-enabled", config.unit, check=False).returncode == 0}


def ready(config: LaunchConfig) -> bool:
    from .cli import local_request

    grant = None
    try:
        grant = local_request(Path(config.state_dir), {"action": "ephemeral"})
        origin = f"http://127.0.0.1:{config.port}"
        if grant["origin"] != origin:
            raise ValueError("A different service uses this state directory.")
        with httpx.Client(base_url=origin, trust_env=False, timeout=2,
                          headers={"Authorization": "Bearer " + grant["credential"]}) as client:
            health = client.get("/api/v1/health")
            session = client.get("/api/v1/session")
            return (health.status_code == 200 and health.json().get("status") == "ok"
                    and session.status_code == 200
                    and session.json().get("mode") == ("demo" if config.demo else "live"))
    except (OSError, ValueError, KeyError, httpx.HTTPError):
        return False
    finally:
        if grant:
            with suppress(OSError, ValueError):
                local_request(Path(config.state_dir), {"action": "revoke", "id": grant["id"]})


def start(path: Path) -> LaunchConfig:
    path = path.absolute()
    with startup_lock(path):
        config = load(path)
        verify_unit(config, path)
        if ready(config):
            return config
        systemctl("start", config.unit)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if ready(config):
                return config
            state = systemctl("is-active", config.unit, check=False).stdout.strip()
            if state == "failed":
                break
            time.sleep(0.2)
        raise ValueError(f"FICC did not become ready. Run journalctl --user -u {config.unit} -n 40.")


def status(path: Path) -> dict:
    config = load(path.absolute())
    verify_unit(config, path.absolute())
    state = systemctl("is-active", config.unit, check=False).stdout.strip()
    return {"unit": config.unit, "state": state, "ready": ready(config),
            "origin": f"http://127.0.0.1:{config.port}", "state_dir": config.state_dir,
            "autostart": systemctl("is-enabled", config.unit, check=False).returncode == 0}


def stop(path: Path) -> dict:
    path = path.absolute()
    with startup_lock(path):
        config = load(path)
        verify_unit(config, path)
        systemctl("stop", config.unit)
    return {"unit": config.unit, "stopped": True, "remote_jobs_cancelled": False}


def open_console(state_dir: Path, print_url: bool = False) -> None:
    from .cli import local_request

    grant = local_request(state_dir, {"action": "bootstrap"})
    url = grant["origin"] + "/#bootstrap=" + quote(grant["credential"], safe="")
    if print_url:
        print(url)
        return
    opener = shutil.which("xdg-open")
    if not opener:
        raise ValueError("Install xdg-utils to open the console, or use ficc open --print-url explicitly.")
    process = subprocess.Popen([opener, url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        code = process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        return
    if code:
        raise ValueError("The browser could not open. Set a default browser or use ficc open --print-url.")


def launch(path: Path) -> None:
    config = start(path)
    open_console(Path(config.state_dir))


def notify_failure(message: str) -> None:
    notifier = shutil.which("notify-send")
    if notifier:
        with suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run([notifier, "--urgency=critical", "FICC could not open", message],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
