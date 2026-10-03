# SPDX-License-Identifier: Apache-2.0
"""Check native runtime installation, source correspondence and discovery refusal."""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from ficc import native_runtime as native

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from viewer_dependencies import source_index  # noqa: E402
from viewer_runtime import install, inventory  # noqa: E402


def runtime(path):
    path.mkdir(mode=0o755)
    for name in native.REQUIRED:
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(('Distinct runtime member: ' + name).encode())
    for directory in path.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    inventory(path, 1750369721)
    return path


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_inventory_checks_distinct_files_and_installation(tmp_path, count):
    source = runtime(tmp_path / 'source')
    for i in range(count):
        (source / 'lib' / f'extra-{i}.so').write_bytes(f'distinct ELF fixture {i}'.encode())
    (source / native.MANIFEST).unlink()
    inventory(source, 1750369721)
    target = install(source, tmp_path / 'installed')
    assert native.validate(target) == native.validate(source)
    (target / 'lib' / f'extra-{count - 1}.so').write_bytes(b'changed')
    with pytest.raises(ValueError, match='differs'):
        native.validate(target)
    native.validate(source)


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo', 'extra', 'missing', 'writable', 'privilege'])
def test_untrusted_files_refused(tmp_path, kind):
    source = runtime(tmp_path / 'source')
    target = source / 'lib/libguac.so.25'
    if kind in {'symlink', 'hardlink', 'fifo', 'missing'}:
        target.unlink()
    if kind == 'symlink':
        target.symlink_to(source / 'NOTICE')
    elif kind == 'hardlink':
        os.link(source / 'NOTICE', target)
    elif kind == 'fifo':
        os.mkfifo(target)
    elif kind == 'extra':
        (source / 'extra').write_bytes(b'unknown')
    elif kind == 'writable':
        target.chmod(0o666)
    elif kind == 'privilege':
        target.chmod(0o4644)
    with pytest.raises(ValueError):
        install(source, tmp_path / 'installed')
    assert not (tmp_path / 'installed').exists()


@pytest.mark.parametrize('field', ['architecture', 'distribution', 'version', 'libc_version'])
def test_platform_mismatch_refused(tmp_path, field):
    source = runtime(tmp_path / 'source')
    path = source / native.MANIFEST
    value = json.loads(path.read_text())
    value['platform'][field] = 'different'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='platform'):
        native.discover(source)


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'lib//empty', 'lib/./dot',
                                 'sources/~../..//outside', 'sources/name\n.dsc', 'sources/name\\file'])
def test_manifest_paths_rejected(tmp_path, name):
    source = runtime(tmp_path / 'source')
    path = source / native.MANIFEST
    value = json.loads(path.read_text())
    value['files'][name] = value['files']['NOTICE']
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='entry'):
        native.validate(source)


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distribution_source_versions_keep_tilde_names(tmp_path, count):
    source = runtime(tmp_path / 'source')
    for index in range(count):
        (source / 'sources' / f'library-{index}_1.2-3ubuntu4~24.04.1.dsc').write_bytes(
            f'Distinct source control file {index}'.encode())
    (source / native.MANIFEST).unlink()
    inventory(source, 1750369721)
    target = install(source, tmp_path / 'installed')
    assert native.validate(target) == native.validate(source)
    for index in range(count):
        assert (target / 'sources' / f'library-{index}_1.2-3ubuntu4~24.04.1.dsc').read_bytes() == (
            f'Distinct source control file {index}'.encode())


@pytest.mark.parametrize('protocols', [['rdp'], ['vnc', 'rdp', 'ssh'], ['vnc', 'vnc'], ['rdp', 'vnc'], [], 'vnc'])
def test_manifest_refuses_unqualified_protocol_sets(tmp_path, protocols):
    source = runtime(tmp_path / 'source')
    path = source / native.MANIFEST
    value = json.loads(path.read_text())
    value['protocols'] = protocols
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='manifest'):
        native.validate(source)


@pytest.mark.parametrize('missing', [None, *sorted(native.RDP_REQUIRED)])
def test_rdp_protocol_requires_each_recorded_library(tmp_path, missing):
    source = runtime(tmp_path / 'source')
    for name in native.RDP_REQUIRED - ({missing} if missing else set()):
        path = source / name
        path.write_bytes(('Distinct RDP member: ' + name).encode())
    path = source / native.MANIFEST
    path.unlink()
    inventory(source, 1750369721)
    value = json.loads(path.read_text())
    value['protocols'] = ['vnc', 'rdp']
    path.write_text(json.dumps(value))
    if missing:
        with pytest.raises(ValueError, match='incomplete'):
            native.validate(source)
    else:
        assert native.validate(source)['protocols'] == ['vnc', 'rdp']


def test_vnc_runtime_refuses_rdp_before_native_process_start(tmp_path, monkeypatch):
    from ficc.errors import Failure
    from ficc.viewer_process import ViewerProcess

    source = runtime(tmp_path / 'source')
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError('An unavailable display protocol started a process')

    monkeypatch.setattr('ficc.viewer_process.subprocess.Popen', forbidden)
    with pytest.raises(Failure, match='required display protocol'):
        ViewerProcess(source, protocol='rdp')
    assert calls == []


def test_discovery_is_adjacent_and_explicit_override_wins(tmp_path, monkeypatch):
    prefix = tmp_path / 'python'
    prefix.mkdir(mode=0o755)
    monkeypatch.setattr(native.sys, 'prefix', str(prefix))
    assert native.discover() is None
    portable = runtime(tmp_path / 'viewer-runtime')
    assert native.discover() == portable
    venv = runtime(prefix / 'viewer-runtime')
    assert native.discover() == venv
    explicit = runtime(tmp_path / 'explicit')
    assert native.discover(explicit) == explicit
    (venv / 'NOTICE').write_bytes(b'changed')
    with pytest.raises(ValueError):
        native.discover()
    assert native.discover(explicit) == explicit


def test_install_never_replaces_an_existing_path(tmp_path):
    source = runtime(tmp_path / 'source')
    target = tmp_path / 'existing'
    target.mkdir()
    with pytest.raises(ValueError, match='must be new'):
        install(source, target)
    assert list(target.iterdir()) == []
    assert not list(tmp_path.glob('.viewer-*'))


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_source_control_requires_every_exact_source_member(tmp_path, count):
    rows = []
    for index in range(count):
        data = ('distinct source ' + str(index)).encode()
        name = f'part-{index}.tar.gz'
        (tmp_path / name).write_bytes(data)
        rows.append(f' {hashlib.sha256(data).hexdigest()} {len(data)} {name}')
    (tmp_path / 'source.dsc').write_text('Format: 3.0 (quilt)\nSource: example\nVersion: 1.2-3\nChecksums-Sha256:\n'
                                        + '\n'.join(rows) + '\n')
    assert len(source_index(tmp_path)[('example', '1.2-3')][1]) == count
    (tmp_path / f'part-{count - 1}.tar.gz').write_bytes(b'changed')
    with pytest.raises(ValueError, match='checksum'):
        source_index(tmp_path)


def test_source_control_cannot_read_an_external_path(tmp_path):
    (tmp_path / 'source.dsc').write_text('Source: example\nVersion: 1\nChecksums-Sha256:\n '
                                        + 'a' * 64 + ' 1 ../outside\n')
    with pytest.raises(ValueError, match='source member'):
        source_index(tmp_path)


@pytest.mark.skipif(os.environ.get('FICC_VIEWER_DISTRIBUTION_TESTS') != '1',
                    reason='Set FICC_VIEWER_DISTRIBUTION_TESTS=1 with an actual built runtime')
def test_real_runtime_is_relocatable_and_loads_vnc(tmp_path):
    import signal
    import socket
    import subprocess
    import time

    source = Path(os.environ['FICC_VIEWER_RUNTIME'])
    target = install(source, tmp_path / 'moved-runtime')
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LD_LIBRARY_PATH': str(target / 'lib')}
    result = subprocess.run([target / 'sbin/guacd', '-v'], env=env, capture_output=True, timeout=5)
    assert result.returncode == 0 and b'1.6.0' in result.stdout + result.stderr
    reservation = socket.socket()
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
    reservation.close()
    process = subprocess.Popen([target / 'sbin/guacd', '-f', '-b', '127.0.0.1', '-l', str(port)],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                stream = socket.create_connection(('127.0.0.1', port), timeout=1)
                break
            except OSError:
                if time.monotonic() >= deadline or process.poll() is not None:
                    raise
                time.sleep(0.02)
        with stream:
            stream.sendall(b'6.select,3.vnc;')
            data = b''
            while b';' not in data and len(data) < 65536:
                block = stream.recv(4096)
                assert block
                data += block
            assert data.startswith(b'4.args,') and b'hostname' in data and b'port' in data
    finally:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
