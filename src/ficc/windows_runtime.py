# SPDX-License-Identifier: Apache-2.0
"""Validate and discover a separate platform-bound Windows transport runtime."""

import json
import os
import re
import stat
import sys
from pathlib import Path

from .native_runtime import checksum, host_platform, safe_directory

MANIFEST = 'windows-runtime.json'
REQUIRED = {'python/bin/python3', 'helper/entry.py', 'helper/ficc/windows_helper.py',
            'helper/ficc/windows_http.py', 'sources/inputs.json', 'NOTICE', 'sbom.cdx.json'}
MAX_BYTES = 384 * 1024 * 1024


def validate(path):
    path = safe_directory(Path(path))
    manifest = path / MANIFEST
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('The Windows runtime manifest is absent or too large.')
    value = json.loads(manifest.read_text())
    if (not isinstance(value, dict) or set(value) != {'schema', 'platform', 'files'}
            or value['schema'] != 1 or type(value['schema']) is not int or value['platform'] != host_platform()):
        raise ValueError('The Windows runtime requires its recorded build platform.')
    files = value['files']
    if not isinstance(files, dict) or not REQUIRED <= files.keys() or not len(files) <= 5000:
        raise ValueError('The Windows runtime inventory is incomplete.')
    total = 0
    for name, entry in files.items():
        if (not isinstance(name, str) or len(name) > 256 or not re.fullmatch(r'[A-Za-z0-9_+./:~=-]+', name)
                or any(part in {'', '.', '..'} for part in name.split('/')) or name == MANIFEST
                or not isinstance(entry, dict) or set(entry) != {'sha256', 'size', 'mode'}
                or type(entry['size']) is not int or not 0 <= entry['size'] <= MAX_BYTES
                or type(entry['mode']) is not int or entry['mode'] not in {0o644, 0o755}
                or not isinstance(entry['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])):
            raise ValueError('The Windows runtime inventory entry is invalid.')
        total += entry['size']
        if total > MAX_BYTES:
            raise ValueError('The Windows runtime exceeds its byte limit.')
    seen = set()
    for item in path.rglob('*'):
        info = item.lstat()
        if info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
            raise ValueError('The Windows runtime file is not trusted.')
        if stat.S_ISDIR(info.st_mode):
            continue
        name = item.relative_to(path).as_posix()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('The Windows runtime contains a link or special file.')
        if name == MANIFEST:
            continue
        entry = files.get(name)
        if (entry is None or stat.S_IMODE(info.st_mode) != entry['mode']
                or info.st_size != entry['size'] or checksum(item) != entry['sha256']):
            raise ValueError('The Windows runtime file differs from its inventory.')
        seen.add(name)
    if seen != set(files) or files['python/bin/python3']['mode'] != 0o755:
        raise ValueError('The Windows runtime inventory differs from its files.')
    return value


def discover(explicit=None):
    if explicit is not None:
        path = Path(explicit).absolute()
        validate(path)
        return path
    for path in (Path(sys.prefix) / 'windows-runtime', Path(sys.prefix).parent / 'windows-runtime'):
        if path.exists() or path.is_symlink():
            validate(path)
            return path
    return None
