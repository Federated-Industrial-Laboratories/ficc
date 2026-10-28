# SPDX-License-Identifier: Apache-2.0
"""Keep cache administration exclusive with supervisor ownership and active imports."""
from types import SimpleNamespace

import pytest

from ficc.execution.model_cache import ModelCache


def test_second_cache_owner_cannot_remove_an_active_import(tmp_path, monkeypatch):
    configuration = SimpleNamespace(directory=tmp_path)
    # This regression exercises real OS locking independently of the mount contract.
    monkeypatch.setattr(ModelCache, "verify", lambda self: (tmp_path.stat().st_dev, tmp_path.stat().st_ino))
    first = ModelCache(configuration, lambda: [])
    partial = tmp_path / "active.partial"
    try:
        partial.write_bytes(b"incomplete import")
        with pytest.raises(ValueError, match="in use"):
            ModelCache(configuration, lambda: [])
        assert partial.read_bytes() == b"incomplete import"
    finally:
        first.close()
    recovered = ModelCache(configuration, lambda: [])
    try:
        assert not partial.exists()
    finally:
        recovered.close()
