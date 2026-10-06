# SPDX-License-Identifier: Apache-2.0
"""Check native launcher identity, quoting and bounded readiness failures."""

import json
import plistlib
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from ficc import launcher_macos as mac
from ficc.launcher_config import load, write_file


@pytest.fixture
def installed(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    executable = tmp_path / "bin with spaces" / "ficc '$dollar"
    executable.parent.mkdir()
    output = tmp_path / "arguments.json"
    executable.write_text(f"#!{sys.executable}\nimport json,sys\n"
                          f"open({str(output)!r},'w').write(json.dumps(sys.argv[1:]))\n")
    executable.chmod(0o755)
    monkeypatch.setattr(mac, "executable", lambda: executable)
    calls = []
    def launchctl(*args, check=True):
        calls.append(args)
        return subprocess.CompletedProcess(args, 113 if args[0] == "print" else 0, "", "")
    monkeypatch.setattr(mac, "launchctl", launchctl)
    args = SimpleNamespace(name="ficc", launcher_config=tmp_path / "private config/launcher.json",
        state_dir=tmp_path / "state", port=8170, profile=["rack-01"], ssh_config=None,
        demo=False, autostart=False)
    mac.install(args)
    config = load(args.launcher_config)
    calls.clear()
    return args.launcher_config, config, calls, output


def test_app_preserves_literal_paths_and_profiles(installed):
    path, config, _, output = installed
    subprocess.run([str(Path(config.desktop_path) / "Contents/MacOS/ficc")], check=True, timeout=3)
    assert json.loads(output.read_text()) == ["launch", "--launcher-config", str(path)]
    job = plistlib.loads(Path(config.unit_path).read_bytes())
    assert job["ProgramArguments"][-2:] == ["--profile", "rack-01"]
    assert job["RunAtLoad"] is False and job["KeepAlive"] is False


@pytest.mark.parametrize("operation", [mac.start, mac.stop])
def test_altered_job_is_refused_before_service_actions(installed, operation):
    path, config, calls, _ = installed
    job = plistlib.loads(Path(config.unit_path).read_bytes())
    job["ProgramArguments"][0] = "/unrelated/program"
    write_file(Path(config.unit_path), plistlib.dumps(job).decode())
    with pytest.raises(ValueError, match="differs"):
        operation(path)
    assert calls == []


@pytest.mark.parametrize("operation", [mac.start, mac.stop])
def test_other_loaded_job_is_refused(installed, monkeypatch, operation):
    path, _, calls, _ = installed
    def other(*args, check=True):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "\tpath = /unrelated/job.plist\n", "")
    monkeypatch.setattr(mac, "launchctl", other)
    with pytest.raises(ValueError, match="Another launchd job"):
        operation(path)
    assert [args[0] for args in calls] == ["print"]


def test_start_reports_failed_readiness_without_restarting_a_job(installed, monkeypatch):
    path, _, calls, _ = installed
    monkeypatch.setattr(mac.launcher, "ready", lambda config: False)
    monkeypatch.setattr(mac.launcher, "startup_lock", lambda path: nullcontext())
    clock = iter([0, 21])
    monkeypatch.setattr(mac.time, "monotonic", lambda: next(clock))
    with pytest.raises(ValueError, match="did not become ready"):
        mac.start(path)
    assert [args[0] for args in calls] == ["print", "print", "bootstrap", "kickstart"]
    assert all("-k" not in args for args in calls)
