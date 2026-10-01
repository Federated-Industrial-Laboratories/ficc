# SPDX-License-Identifier: Apache-2.0
"""Bind copied transport helpers to the controller source used by a release."""

from .common import digest

WINDOWS_HELPERS = ('windows_helper.py', 'windows_http.py', 'module_windows_spec.py',
                   'module_windows_private.py', 'native_runtime.py', 'settings.py', 'windows_runtime.py')


def verify_windows_sources(runtime, sources):
    """Refuse an older transport helper even when its own inventory is valid."""
    for name in WINDOWS_HELPERS:
        path = runtime / 'helper/ficc' / name
        expected = sources.get('src/ficc/' + name)
        if not expected or path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError('Rebuild the Windows transport from the selected controller source: ' + name)
    return len(WINDOWS_HELPERS)
