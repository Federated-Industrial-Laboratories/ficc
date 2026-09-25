# SPDX-License-Identifier: Apache-2.0
"""Verify persistent AppImage paths and first-use desktop behaviour."""

import os
import sys

import pytest

from ficc import launcher, launcher_runtime
from ficc.cli import parser
from ficc.launcher_config import desktop_text
from ficc.launcher_runtime import executable


def appimage(tmp_path, monkeypatch):
    mount = tmp_path / "temporary mount"
    interpreter = mount / "usr/lib/ficc/python/bin/python3"
    interpreter.parent.mkdir(parents=True)
    interpreter.touch()
    image = tmp_path / 'saved image $cash %u "quote".AppImage'
    image.write_bytes(b"\x7fELF\0\0\0\0AI\x02\0")
    image.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(interpreter))
    monkeypatch.setenv("APPDIR", str(mount))
    monkeypatch.setenv("APPIMAGE", str(image))
    return mount, image


def test_appimage_stages_a_persistent_service_runtime(tmp_path, monkeypatch):
    mount, image = appimage(tmp_path, monkeypatch)
    command = tmp_path / "installed/ficc"
    sources = []
    monkeypatch.setattr(launcher_runtime, "install", lambda source: sources.append(source) or command)
    assert executable() == command
    assert sources == [mount / "usr/lib/ficc"]
    assert not executable().is_relative_to(mount)


@pytest.mark.parametrize("change", ["relative", "writable", "not-image", "not-executable", "fifo"])
def test_invalid_appimage_reference_is_refused(tmp_path, monkeypatch, change):
    _, image = appimage(tmp_path, monkeypatch)
    if change == "relative":
        monkeypatch.setenv("APPIMAGE", "relative.AppImage")
    elif change == "writable":
        image.chmod(0o777)
    elif change == "not-image":
        image.write_bytes(b"#!/bin/sh\nexit 0\n")
    elif change == "fifo":
        image.unlink()
        os.mkfifo(image)
    else:
        image.chmod(0o644)
    with pytest.raises(ValueError):
        executable()


def test_unrelated_appimage_environment_does_not_override_installed_command(tmp_path, monkeypatch):
    _, image = appimage(tmp_path, monkeypatch)
    installed = tmp_path / "installation/bin/ficc"
    installed.parent.mkdir(parents=True)
    installed.touch()
    installed.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(installed.with_name("python3")))
    assert executable() == installed
    assert executable() != image


def test_first_desktop_use_installs_once_without_autostart(tmp_path, monkeypatch):
    path = tmp_path / "launcher.json"
    calls = []
    monkeypatch.setattr(os, "getuid", lambda: 1000)

    def install(args, **kwargs):
        calls.append((args, kwargs))
        path.touch()

    monkeypatch.setattr(launcher, "install", install)
    monkeypatch.setattr(launcher, "launch", lambda value: calls.append(value))
    launcher.desktop(path)
    launcher.desktop(path)
    assert len(calls) == 3
    args, flags = calls[0]
    assert args.autostart is False and args.profile == []
    assert flags == {"only_if_missing": True}
    assert calls[1:] == [path, path]


def test_desktop_never_installs_over_an_existing_configuration(tmp_path, monkeypatch):
    path = tmp_path / "existing.json"
    path.write_text("existing")
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(launcher, "install", lambda *a, **k: pytest.fail("replaced configuration"))
    calls = []
    monkeypatch.setattr(launcher, "launch", calls.append)
    launcher.desktop(path)
    assert calls == [path] and path.read_text() == "existing"


def test_desktop_refuses_root(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0)
    with pytest.raises(ValueError, match="without sudo"):
        launcher.desktop(tmp_path / "launcher.json")


def test_desktop_icon_survives_an_appimage_unmount(tmp_path):
    from ficc.launcher_config import LaunchConfig

    path = tmp_path / "launcher.json"
    value = LaunchConfig("/opt/ficc/ficc", str(tmp_path / "state"),
                         str(tmp_path / "ficc.service"), str(tmp_path / "ficc.desktop"))
    assert "Icon=" + str(path.with_suffix(".svg")) in desktop_text(value, path)


def test_version_does_not_start_the_service(capsys):
    with pytest.raises(SystemExit) as result:
        parser().parse_args(["--version"])
    assert result.value.code == 0 and "FICC 0.1.0rc1" in capsys.readouterr().out


@pytest.mark.parametrize("changed", [False, True])
def test_desktop_explicit_settings_preserve_saved_configuration(tmp_path, monkeypatch, changed):
    from ficc.launcher_config import LaunchConfig, save

    path = tmp_path / "launcher.json"
    state = tmp_path / "state"
    config = LaunchConfig("/opt/ficc/ficc", str(state), str(tmp_path / "ficc-check.service"),
                          str(tmp_path / "ficc.desktop"), 8185, ("rack-01",), demo=True)
    save(path, config)
    original = path.read_bytes()
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    launched = []
    monkeypatch.setattr(launcher, "launch", launched.append)
    options = {"state_dir": state, "port": 8186 if changed else 8185, "profile": ["rack-01"],
               "name": "ficc-check", "demo": True}
    if changed:
        with pytest.raises(ValueError, match="differ from the saved launcher"):
            launcher.desktop(path, options)
        assert not launched
    else:
        launcher.desktop(path, options)
        assert launched == [path]
    assert path.read_bytes() == original


def test_desktop_cli_does_not_impose_defaults_on_saved_configuration():
    args = parser().parse_args(["desktop"])
    assert not ({"state_dir", "port", "profile", "demo", "name"} & vars(args).keys())
