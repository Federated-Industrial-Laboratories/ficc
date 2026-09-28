# SPDX-License-Identifier: Apache-2.0
"""Build the pinned RDP client libraries without desktop or device services."""

import hashlib
from pathlib import Path

OFF = ('CLIENT', 'SERVER', 'X11', 'WAYLAND', 'SDL', 'SAMPLE', 'MANPAGES',
       'WINPR_TOOLS', 'FFMPEG', 'SWSCALE', 'OPENH264', 'ALSA', 'PULSE', 'OSS',
       'SNDIO', 'CUPS', 'PCSC', 'PCSC_WINPR', 'SMARTCARD_EMULATE', 'PKCS11',
       'KRB5', 'GSSAPI', 'AAD', 'WINPR_JSON', 'URIPARSER', 'CCACHE', 'CLANG_FORMAT',
       'RDTK', 'THIRD_PARTY', 'DEBUG_ALL', 'DEBUG_SYMBOLS', 'OPENCL', 'FUSE')


def patches(run, root, source, entries):
    """Apply the checked upstream GDI callback repair before compiling Guacamole."""
    if len(entries) != 1:
        raise ValueError('The RDP callback repair is required.')
    for entry in entries:
        if entry['name'] != 'viewer-guacamole-postconnect.patch':
            raise ValueError('The RDP source repair name differs.')
        path = source / entry['name']
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('The RDP source repair hash differs.')
        run(['patch', '--batch', '--fuzz=0', '-p1', '-i', path], cwd=root)


def build(run, root: Path, work: Path, prefix: Path, flags: str, jobs: int) -> None:
    """Build only the shared libraries needed by the host RDP decoder."""
    directory = work / 'rdp-build'
    flags = flags.replace('-ffile-prefix-map=' + str(work) + '=/build',
                          '-ffile-prefix-map=' + str(root) + '=/build/freerdp')
    flags += ' -ffile-prefix-map=' + str(directory) + '=/build/rdp-build'
    run(['cmake', '-S', root, '-B', directory,
         '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=/viewer',
         '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_SKIP_RPATH=ON',
         '-DCMAKE_C_FLAGS=' + flags, '-DCMAKE_CXX_FLAGS=' + flags,
         '-DBUILD_SHARED_LIBS=ON', '-DBUILD_TESTING=OFF', '-DBUILD_TESTING_INTERNAL=OFF',
         '-DWITH_CLIENT_COMMON=ON', '-DWITH_OPENSSL=ON', '-DWITH_JSON_DISABLED=ON',
         '-DWITH_UNICODE_BUILTIN=ON',
         '-DCHANNEL_URBDRC=OFF', '-DCHANNEL_SMARTCARD=OFF',
         *['-DWITH_' + name + '=OFF' for name in OFF]])
    run(['cmake', '--build', directory, '--parallel', str(jobs)])
    run(['cmake', '--install', directory, '--prefix', prefix])


def libraries(prefix: Path) -> list[Path]:
    """Select client and runtime libraries; exclude server programs and tools."""
    paths = []
    for pattern in ('libfreerdp3.so*', 'libfreerdp-client3.so*', 'libwinpr3.so*'):
        selected = sorted((prefix / 'lib').glob(pattern))
        if not selected:
            raise ValueError('RDP build library is absent: ' + pattern)
        paths.extend(selected)
    return paths


def notices(root: Path, destination: Path) -> None:
    """Retain the bundled runtime source notices with the native distribution."""
    names = ('crypto/md4.c', 'crypto/md5.c', 'sysinfo/cpufeatures/cpu-features.c',
             'utils/wlog/JournaldAppender.h', 'utils/wlog/SyslogAppender.h',
             'utils/wlog/UdpAppender.h')
    blocks = []
    for name in names:
        source = root / 'winpr/libwinpr' / name
        text = source.read_text()
        end = text.find('*/')
        if not text.startswith('/*') or not 0 < end < 16384:
            raise ValueError('Pinned RDP source notice is absent')
        blocks.append('winpr/libwinpr/' + name + '\n' + text[:end + 2] + '\n')
    blocks.append((root / 'winpr/libwinpr/sysinfo/cpufeatures/NOTICE').read_text())
    destination.write_text('\n'.join(blocks))
