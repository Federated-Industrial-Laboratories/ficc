# SPDX-License-Identifier: Apache-2.0
"""Check the optional RDP build contract and actual relocated decoder loading."""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import viewer_rdp  # noqa: E402
from viewer_runtime import install  # noqa: E402

from ficc.native_runtime import validate  # noqa: E402
from ficc.viewer.wire import parse  # noqa: E402


def test_rdp_build_has_fixed_prefix_tls_and_no_device_services(tmp_path):
    calls = []
    work = tmp_path / 'work'
    source, prefix = work / 'source', work / 'dependencies'
    viewer_rdp.build(calls.append, source, work, prefix,
                     '-O2 -g0 -ffile-prefix-map=' + str(work) + '=/build', 2)
    configure = calls[0]
    for option in ('-DCMAKE_INSTALL_PREFIX=/viewer', '-DWITH_OPENSSL=ON',
                   '-DWITH_CLIENT_COMMON=ON', '-DWITH_SERVER=OFF', '-DWITH_FUSE=OFF',
                   '-DCHANNEL_URBDRC=OFF', '-DCHANNEL_SMARTCARD=OFF', '-DWITH_JSON_DISABLED=ON'):
        assert option in configure
    assert calls[-1] == ['cmake', '--install', work / 'rdp-build', '--prefix', prefix]
    flags = next(value for value in configure if str(value).startswith('-DCMAKE_C_FLAGS='))
    assert str(source) in flags and str(work / 'rdp-build') in flags


@pytest.mark.parametrize('missing', ['libfreerdp3.so.3', 'libfreerdp-client3.so.3', 'libwinpr3.so.3'])
def test_rdp_build_requires_every_runtime_library(tmp_path, missing):
    directory = tmp_path / 'lib'
    directory.mkdir()
    for name in {'libfreerdp3.so.3', 'libfreerdp-client3.so.3', 'libwinpr3.so.3'} - {missing}:
        (directory / name).write_bytes(b'library fixture')
    with pytest.raises(ValueError, match='absent'):
        viewer_rdp.libraries(tmp_path)


@pytest.mark.skipif(os.environ.get('FICC_VIEWER_RDP_TESTS') != '1',
                    reason='Set FICC_VIEWER_RDP_TESTS=1 with an actual RDP runtime')
@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_real_relocated_rdp_decoder_parameters_and_inventory(tmp_path, count):
    source = Path(os.environ['FICC_VIEWER_RUNTIME'])
    target = install(source, tmp_path / 'moved-runtime')
    manifest = validate(target)
    assert manifest['protocols'] == ['vnc', 'rdp']
    build = json.loads((target / 'sources/build.json').read_text())
    assert any(item['id'] == 'freerdp' and item['version'] == '3.32.1' for item in build['inputs']['inputs'])
    assert (target / 'licenses/freerdp-SOURCE-NOTICES').stat().st_size > 1000
    for path in (target / 'lib').iterdir():
        if path.name.startswith(('libfreerdp', 'libwinpr')):
            assert str(source.parent).encode() not in path.read_bytes()
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LD_LIBRARY_PATH': str(target / 'lib')}
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen([target / 'sbin/guacd', '-f', '-b', '127.0.0.1', '-l', str(port)],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        for _ in range(count):
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
                stream.sendall(b'6.select,3.rdp;')
                data = b''
                while b';' not in data and len(data) < 65536:
                    block = stream.recv(4096)
                    assert block
                    data += block
                values = parse(data.decode(), maximum=65536)
                assert values[0] == 'args'
                assert {'hostname', 'port', 'username', 'password', 'domain', 'security',
                        'preconnection-blob', 'cert-fingerprints', 'ignore-cert', 'cert-tofu',
                        'disable-auth', 'disable-copy', 'disable-paste', 'disable-audio',
                        'enable-audio-input', 'enable-printing', 'enable-drive', 'read-only'} <= set(values[1:])
    finally:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_rdp_requires_the_pinned_upstream_callback_repair(tmp_path):
    import hashlib
    calls = []
    path = tmp_path / 'viewer-guacamole-postconnect.patch'
    path.write_text('checked repair fixture')
    entry = {'name': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    viewer_rdp.patches(lambda command, **options: calls.append((command, options)),
                       tmp_path / 'source', tmp_path, [entry])
    assert calls == [(['patch', '--batch', '--fuzz=0', '-p1', '-i', path], {'cwd': tmp_path / 'source'})]
    path.write_text('changed repair fixture')
    with pytest.raises(ValueError, match='hash differs'):
        viewer_rdp.patches(lambda *args, **kwargs: None, tmp_path, tmp_path, [entry])
    with pytest.raises(ValueError, match='required'):
        viewer_rdp.patches(lambda *args, **kwargs: None, tmp_path, tmp_path, [])
