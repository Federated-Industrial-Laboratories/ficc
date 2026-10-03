# SPDX-License-Identifier: Apache-2.0
"""Refuse unsafe driver configuration before loading installation code."""

import json
from types import SimpleNamespace

import pytest

from ficc import state_provider
from ficc.state_provider import CONFIG, configuration, open_provider, read_private


@pytest.mark.parametrize("unsafe", ["permissions", "symlink", "hardlink", "directory", "oversized"])
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_private_configuration_rejects_unsafe_files(tmp_path, unsafe, count):
    for index in range(count):
        folder = tmp_path / str(index)
        folder.mkdir(mode=0o700)
        source = folder / CONFIG
        source.write_text(json.dumps({"provider": f"synthetic-{index}", "configuration": {}}))
        source.chmod(0o600)
        if unsafe == "permissions":
            source.chmod(0o640)
        elif unsafe == "symlink":
            saved = source.rename(folder / "saved")
            source.symlink_to(saved)
        elif unsafe == "hardlink":
            (folder / "linked").hardlink_to(source)
        elif unsafe == "directory":
            source.unlink()
            source.mkdir(mode=0o700)
        else:
            source.write_bytes(bytes([index]) * 65537)
        with pytest.raises((ValueError, OSError)):
            configuration(folder)


@pytest.mark.parametrize("case", ["missing", "duplicate", "version"])
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_driver_registration_must_be_unique_and_compatible(tmp_path, monkeypatch, case, count):
    for index in range(count):
        folder = tmp_path / str(index)
        folder.mkdir(mode=0o700)
        source = folder / CONFIG
        source.write_text(json.dumps({"provider": f"synthetic-{index}", "configuration": {}}))
        source.chmod(0o600)
        calls = []
        def load():
            calls.append("loaded")
            return SimpleNamespace(API_VERSION=999)
        entry = SimpleNamespace(load=load)
        monkeypatch.setattr(state_provider.importlib.metadata, "entry_points",
                            lambda **kwargs: [] if case == "missing" else [entry, entry] if case == "duplicate" else [entry])
        with pytest.raises(ValueError):
            open_provider(folder)
        assert calls == (["loaded"] if case == "version" else [])
        assert not (folder / state_provider.BINDING).exists()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_private_input_is_bounded_and_preserves_exact_bytes(tmp_path, count):
    for index in range(count):
        folder = tmp_path / str(index)
        folder.mkdir(mode=0o700)
        source = folder / "password"
        source.write_bytes(bytes([index]) + b"utf8-independent\n")
        source.chmod(0o600)
        assert read_private(source) == bytes([index]) + b"utf8-independent\n"
        with pytest.raises(ValueError):
            read_private(source, 4)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_state_cli_reports_storage_failure_without_details_or_traceback(tmp_path, monkeypatch, capsys, count):
    for index in range(count):
        folder = tmp_path / str(index)
        folder.mkdir(mode=0o700)
        from ficc import cli, state_cli
        from ficc.state_provider import StorageFailure
        source = folder / "input.json"
        source.write_text(json.dumps({"provider": f"synthetic-{index}", "configuration": {}}))
        source.chmod(0o600)
        def unavailable(*args):
            raise StorageFailure("private-driver-detail")
        monkeypatch.setattr(state_cli, "open_provider", unavailable)
        assert cli.main(["state-configure", "--state-dir", str(folder / "state"), "--input", str(source)]) == 1
        output = capsys.readouterr()
        assert not output.out
        assert output.err == "The state database is unavailable. Check connection settings, ownership, and pending writes.\n"
