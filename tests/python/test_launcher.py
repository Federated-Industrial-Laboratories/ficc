# SPDX-License-Identifier: Apache-2.0
"""Verify startup ownership, private configuration and bounded browser launch."""

import argparse
import json
import os
import subprocess
from pathlib import Path

import pytest

from ficc import launcher
from ficc.cli import parser
from ficc.launcher_config import LaunchConfig, desktop_text, load, save, unit_text, write_file


def configured(tmp_path):
    root = tmp_path / "config"
    root.mkdir(mode=0o700)
    path = root / "launcher.json"
    config = LaunchConfig("/opt/ficc/bin/ficc", str(tmp_path / "state"),
                          str(tmp_path / "ficc.service"), str(tmp_path / "ficc.desktop"),
                          profiles=("rack-01", "rack-02"))
    save(path, config)
    write_file(Path(config.unit_path), unit_text(config, path))
    return path, config


def test_configuration_is_private_and_round_trips(tmp_path):
    path, config = configured(tmp_path)
    assert load(path) == config
    assert path.stat().st_mode & 0o777 == 0o600
    assert "--profile" in config.command()
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        load(path)


def test_configuration_rejects_links_and_unknown_versions(tmp_path):
    path, _ = configured(tmp_path)
    original = path.with_name("original.json")
    path.rename(original)
    path.symlink_to(original)
    with pytest.raises(OSError):
        load(path)
    with pytest.raises(ValueError, match="regular"):
        write_file(path, "replacement")
    assert "executable" in original.read_text()
    path.unlink()
    write_file(path, json.dumps({"version": 99}))
    with pytest.raises(ValueError, match="version"):
        load(path)


@pytest.mark.parametrize("hostile", ["/tmp/bad\nExecStart=/bin/false", "/tmp/bad\0", "/tmp/bad\t", "relative"])
def test_configuration_refuses_unsafe_paths(tmp_path, hostile):
    _, config = configured(tmp_path)
    with pytest.raises(ValueError):
        LaunchConfig(hostile, config.state_dir, config.unit_path, config.desktop_path)


def test_generated_files_keep_data_out_of_shell_syntax(tmp_path):
    path, config = configured(tmp_path)
    config.executable = '/opt/space $HOME `echo bad` %u "quote" \\ slash/bin/ficc'
    service, desktop = unit_text(config, path), desktop_text(config, path)
    assert "$$HOME" in service and "%%u" in service
    assert "\\\\$HOME" in desktop and "%%u" in desktop
    assert "\\\\\\\\ slash" in desktop
    assert "sh -c" not in service and "sh -c" not in desktop
    assert "bootstrap=" not in desktop + service


def test_existing_ready_service_does_not_start_again(tmp_path, monkeypatch):
    path, config = configured(tmp_path)
    calls = []
    monkeypatch.setattr(launcher, "verify_unit", lambda *args: None)
    monkeypatch.setattr(launcher, "ready", lambda value: True)
    monkeypatch.setattr(launcher, "systemctl", lambda *args, **kwargs: calls.append(args))
    assert launcher.start(path) == config
    assert calls == []


def test_stop_verifies_unit_before_touching_service(tmp_path, monkeypatch):
    path, _ = configured(tmp_path)
    calls = []

    def refuse(*args):
        raise ValueError("Different service")

    monkeypatch.setattr(launcher, "verify_unit", refuse)
    monkeypatch.setattr(launcher, "systemctl", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match="Different"):
        launcher.stop(path)
    assert calls == []


def test_overridden_unit_is_refused(tmp_path, monkeypatch):
    path, config = configured(tmp_path)

    def systemctl(*args, **kwargs):
        stdout = config.unit_path if "--property=FragmentPath" in args else "/tmp/override.conf"
        return subprocess.CompletedProcess(args, 0, stdout, "")

    monkeypatch.setattr(launcher, "systemctl", systemctl)
    with pytest.raises(ValueError, match="overrides"):
        launcher.verify_unit(config, path)


def test_install_does_not_replace_unmanaged_desktop(tmp_path, monkeypatch):
    import sys

    executable = tmp_path / "venv/bin/ficc"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    monkeypatch.setattr(sys, "executable", str(executable.with_name("python")))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    desktop = tmp_path / "data/applications/ficc.desktop"
    desktop.parent.mkdir(parents=True)
    desktop.write_text("[Desktop Entry]\nName=Existing application\n")
    args = argparse.Namespace(launcher_config=tmp_path / "config/ficc/launcher.json", name="ficc",
                              state_dir=tmp_path / "state", port=8170, profile=[], ssh_config=None,
                              demo=False, autostart=False)
    with pytest.raises(ValueError, match="not managed"):
        launcher.install(args)
    assert "Existing application" in desktop.read_text()


def test_browser_launch_returns_without_waiting_for_browser_exit(tmp_path, monkeypatch, capsys):
    import ficc.cli

    grant = {"origin": "http://127.0.0.1:8170", "credential": "secret-value"}
    monkeypatch.setattr(ficc.cli, "local_request", lambda *args: grant)
    monkeypatch.setattr(launcher.shutil, "which", lambda name: "/usr/bin/xdg-open")
    captured = []

    class Child:
        def __init__(self, command, **kwargs):
            captured.append((command, kwargs))

        def wait(self, timeout):
            assert timeout == 3
            raise subprocess.TimeoutExpired("xdg-open", timeout)

    monkeypatch.setattr(launcher.subprocess, "Popen", Child)
    launcher.open_console(tmp_path)
    assert captured[0][0] == ["/usr/bin/xdg-open", "http://127.0.0.1:8170/#bootstrap=secret-value"]
    assert captured[0][1]["start_new_session"] is True
    assert captured[0][1]["stdout"] == subprocess.DEVNULL
    assert "secret-value" not in capsys.readouterr().out


def test_default_install_is_on_demand():
    args = parser().parse_args(["install-launcher"])
    assert args.autostart is False and args.name == "ficc"


def test_private_log_output_preserves_binary_without_terminal_escape(tmp_path, monkeypatch, capsys):
    import base64

    import httpx

    import ficc.cli
    from ficc.job_cli import execute

    monkeypatch.setattr(ficc.cli, "local_request", lambda *args: {
        "origin": "http://127.0.0.1:8170", "credential": "secret", "id": "grant"})
    payload = b"\x1b]52;c;clipboard\x07\xff\x00"
    result = {"data_base64": base64.b64encode(payload).decode(), "next_offset": len(payload)}
    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: httpx.Response(200, json=result))
    output = tmp_path / "output.bin"
    args = parser().parse_args(["job-logs", "operation", "--node", "node", "--output", str(output)])
    execute(args)
    assert output.read_bytes() == payload
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert "\x1b" not in capsys.readouterr().out
