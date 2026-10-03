# SPDX-License-Identifier: Apache-2.0
"""Reject stale helper payloads which do not implement the selected controller protocol."""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from release_lib.runtimes import WINDOWS_HELPERS, verify_windows_sources  # noqa: E402


def runtime(path, index):
    helpers = path / 'helper/ficc'
    helpers.mkdir(parents=True)
    sources = {}
    for name in WINDOWS_HELPERS:
        content = f'helper {name} for source {index}'.encode()
        (helpers / name).write_bytes(content)
        sources['src/ficc/' + name] = hashlib.sha256(content).hexdigest()
    return sources


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_release_uses_exact_matching_transport_helpers(tmp_path, count):
    for index in range(count):
        path = tmp_path / str(index)
        sources = runtime(path, index)
        assert verify_windows_sources(path, sources) == len(WINDOWS_HELPERS)


@pytest.mark.parametrize('name', WINDOWS_HELPERS)
@pytest.mark.parametrize('change', ['stale', 'missing', 'link', 'unbound'])
def test_release_rejects_any_stale_or_unbound_helper(tmp_path, name, change):
    sources = runtime(tmp_path, 1)
    path = tmp_path / 'helper/ficc' / name
    if change == 'stale':
        path.write_text('valid older helper with a different request contract')
    elif change == 'missing':
        path.unlink()
    elif change == 'link':
        target = tmp_path / 'other'
        path.replace(target)
        path.symlink_to(target)
    else:
        sources.pop('src/ficc/' + name)
    with pytest.raises(ValueError, match='Rebuild the Windows transport'):
        verify_windows_sources(tmp_path, sources)
