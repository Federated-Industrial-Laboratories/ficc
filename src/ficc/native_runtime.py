# SPDX-License-Identifier: Apache-2.0
"""Check an installed viewer inventory and select an adjacent runtime."""

import hashlib
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path

MANIFEST = 'viewer-runtime.json'
REQUIRED = {'sbin/guacd', 'lib/libguac.so.25', 'lib/libguac-client-vnc.so',
            'lib/libvncclient.so.1', 'sbom.cdx.json', 'NOTICE', 'sources/build.json'}
RDP_REQUIRED = {'lib/libguac-client-rdp.so', 'lib/libfreerdp3.so.3',
                'lib/libfreerdp-client3.so.3', 'lib/libwinpr3.so.3'}
MAX_BYTES = 512 * 1024 * 1024


def host_platform() -> dict[str, str]:
    release = platform.freedesktop_os_release()
    family, version = platform.libc_ver()
    return {'system': platform.system(), 'architecture': platform.machine(),
            'distribution': release['ID'], 'version': release['VERSION_ID'],
            'libc': family, 'libc_version': version}


def checksum(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def safe_directory(path: Path) -> Path:
    path = path.absolute()
    for part in (path, *path.parents):
        info = part.lstat()
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()}
                or (info.st_mode & 0o022 and not sticky_root)):
            raise ValueError('Viewer runtime directory is not trusted')
    return path


def validate(path: Path, *, check_platform: bool = True) -> dict:
    """Check local file integrity. This does not authenticate a publisher."""
    path = safe_directory(path)
    manifest = path / MANIFEST
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 1024 * 1024:
        raise ValueError('Viewer runtime manifest is absent or too large')
    value = json.loads(manifest.read_text())
    if (not isinstance(value, dict) or set(value) != {'schema', 'protocols', 'platform', 'files'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['protocols'] not in (['vnc'], ['vnc', 'rdp'])
            or not isinstance(value['platform'], dict)
            or set(value['platform']) != set(host_platform())
            or any(not isinstance(v, str) or not 1 <= len(v) <= 128 for v in value['platform'].values())):
        raise ValueError('Viewer runtime manifest is invalid')
    if check_platform and value['platform'] != host_platform():
        raise ValueError('Viewer runtime requires its recorded build platform')
    files = value['files']
    required = REQUIRED | (RDP_REQUIRED if 'rdp' in value['protocols'] else set())
    if not isinstance(files, dict) or not required <= files.keys() or not len(files) <= 512:
        raise ValueError('Viewer runtime inventory is incomplete')
    total = 0
    for name, entry in files.items():
        if (not isinstance(name, str) or len(name) > 256 or not re.fullmatch(r'[A-Za-z0-9_+./:~-]+', name)
                or any(p in {'', '.', '..'} for p in name.split('/')) or name == MANIFEST
                or not isinstance(entry, dict) or set(entry) != {'sha256', 'size', 'mode'}
                or type(entry['size']) is not int or not 0 <= entry['size'] <= MAX_BYTES
                or entry['mode'] not in {0o644, 0o755}
                or not isinstance(entry['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])):
            raise ValueError('Viewer runtime inventory entry is invalid')
        total += entry['size']
        if total > MAX_BYTES:
            raise ValueError('Viewer runtime is too large')
    seen = set()
    for item in path.rglob('*'):
        info = item.lstat()
        if info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
            raise ValueError('Viewer runtime file is not trusted')
        if stat.S_ISDIR(info.st_mode):
            continue
        name = item.relative_to(path).as_posix()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Viewer runtime contains a link or special file')
        if name == MANIFEST:
            continue
        entry = files.get(name)
        if (entry is None or stat.S_IMODE(info.st_mode) != entry['mode']
                or info.st_size != entry['size'] or checksum(item) != entry['sha256']):
            raise ValueError('Viewer runtime file differs from its inventory')
        seen.add(name)
    if seen != set(files) or files['sbin/guacd']['mode'] != 0o755:
        raise ValueError('Viewer runtime inventory does not match its files')
    return value


def discover(explicit: Path | None = None) -> Path | None:
    """Select an explicit path or a runtime adjacent to this interpreter."""
    if explicit is not None:
        path = explicit.absolute()
        validate(path)
        return path
    for path in (Path(sys.prefix) / 'viewer-runtime', Path(sys.prefix).parent / 'viewer-runtime'):
        if path.exists() or path.is_symlink():
            validate(path)
            return path
    return None
