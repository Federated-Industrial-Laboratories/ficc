# SPDX-License-Identifier: Apache-2.0
"""Keep core startup available when an implicit native display runtime is invalid."""

from pathlib import Path

import pytest

from ficc import settings


def test_adjacent_runtime_is_selected_without_a_command_line_path(tmp_path, monkeypatch):
    expected = tmp_path / "viewer-runtime"
    monkeypatch.setattr(settings, "discover", lambda: expected)
    value = settings.Settings(state_dir=tmp_path / "state")
    assert value.viewer_runtime == expected and value.viewer_runtime_error is None


def test_invalid_implicit_runtime_disables_only_display_with_diagnostic(tmp_path, monkeypatch, caplog):
    def invalid():
        raise ValueError("A mismatched platform.")
    monkeypatch.setattr(settings, "discover", invalid)
    value = settings.Settings(state_dir=tmp_path / "state")
    assert value.viewer_runtime is None
    assert "invalid or incompatible" in value.viewer_runtime_error
    assert value.viewer_runtime_error in caplog.text


def test_invalid_explicit_runtime_refuses_configuration(tmp_path, monkeypatch):
    calls = []
    def invalid(path):
        calls.append(path)
        raise ValueError("The selected runtime is invalid.")
    monkeypatch.setattr(settings, "discover", invalid)
    with pytest.raises(ValueError, match="selected runtime"):
        settings.Settings(state_dir=tmp_path / "state", viewer_runtime=Path("viewer-runtime"))
    assert calls == [Path("viewer-runtime")]
