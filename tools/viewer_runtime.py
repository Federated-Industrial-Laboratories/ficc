#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Build or install a checked native viewer. Inputs: pinned sources; exit: zero on success.
"""Build a private viewer runtime or install an existing checked directory."""

import argparse
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import viewer_rdp
from source_runtime import download, secure_dir, unpack
from viewer_dependencies import collect, package

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ficc.native_runtime import MANIFEST, checksum, host_platform, validate  # noqa: E402

VNC_OFF = ('LZO', 'SDL', 'GTK', 'LIBSSHTUNNEL', 'GNUTLS', 'OPENSSL', 'SYSTEMD', 'GCRYPT',
           'FFMPEG', 'TIGHTVNC_FILETRANSFER', 'WEBSOCKETS', 'SASL', 'XCB', 'EXAMPLES', 'TESTS', 'QT')
GUAC_OFF = ('libavcodec', 'libavformat', 'libavutil', 'libswscale', 'ssl', 'vorbis', 'pulse',
            'pango', 'terminal', 'rdp', 'ssh', 'telnet', 'webp', 'websockets')


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def inventory(runtime: Path, epoch: int, protocols: tuple[str, ...] = ('vnc',)) -> None:
    files = {}
    for path in sorted(runtime.rglob('*')):
        if path.is_file():
            mode = 0o755 if path.name == 'guacd' else 0o644
            path.chmod(mode)
            os.utime(path, (epoch, epoch))
            files[path.relative_to(runtime).as_posix()] = {'size': path.stat().st_size,
                                                          'mode': mode, 'sha256': checksum(path)}
    write_json(runtime / MANIFEST, {'schema': 1, 'protocols': list(protocols), 'platform': host_platform(), 'files': files})
    (runtime / MANIFEST).chmod(0o644)
    os.utime(runtime / MANIFEST, (epoch, epoch))


def install(source: Path, destination: Path) -> Path:
    """Install a caller-approved local runtime without replacing an existing path."""
    validate(source)
    parent = secure_dir(destination.absolute().parent)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Viewer destination must be new')
    stage = Path(tempfile.mkdtemp(prefix='.viewer-', dir=parent))
    try:
        shutil.copytree(source, stage / 'runtime', symlinks=True)
        validate(stage / 'runtime')
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(stage / 'runtime'), -100, os.fsencode(destination), 1) != 0:
            raise OSError(ctypes.get_errno(), 'Cannot install viewer runtime without replacement')
    finally:
        shutil.rmtree(stage)
    return destination


def build(args) -> Path:
    if host_platform()['system'] != 'Linux' or host_platform()['architecture'] != 'x86_64':
        raise ValueError('Viewer builds require Linux x86_64')
    for name in ('cc', 'c++', 'make', 'cmake', 'pkg-config', 'readelf', 'dpkg-query'):
        if shutil.which(name) is None:
            raise ValueError('Viewer build tool is absent: ' + name)
    rdp = bool(getattr(args, 'rdp', False))
    headers_needed = ['cairo', 'libpng', 'libjpeg', 'uuid', *(['openssl'] if rdp else [])]
    subprocess.run(['pkg-config', '--exists', *headers_needed], check=True)
    cache = secure_dir(args.cache)
    if args.work.exists() or args.output.exists():
        raise ValueError('Viewer work and output directories must be new')
    work = secure_dir(args.work)
    output = args.output.absolute()
    secure_dir(output.parent)
    if work == output or work.is_relative_to(output) or output.is_relative_to(work):
        raise ValueError('Viewer work and output directories must be separate')
    lock = json.loads((ROOT / 'packaging/viewer-inputs.json').read_text())
    lock['inputs'] = [item for item in lock['inputs'] if item.get('optional') != 'rdp' or rdp]
    archives, roots = {}, {}
    for item in lock['inputs']:
        archives[item['id']] = download(item, cache)
        unpack(archives[item['id']], work / item['id'])
        entries = list((work / item['id']).iterdir())
        if len(entries) != 1 or not entries[0].is_dir():
            raise ValueError('Viewer source archive requires one root')
        roots[item['id']] = entries[0]
    deps, stage = work / 'dependencies', work / 'stage'
    stage.mkdir()
    commands = []
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'LANG': 'C', 'LC_ALL': 'C',
           'SOURCE_DATE_EPOCH': str(args.epoch), 'TZ': 'UTC',
           'CFLAGS': '-O2 -g0 -ffile-prefix-map=' + str(work) + '=/build',
           'CPPFLAGS': '-I' + str(deps / 'include'), 'LDFLAGS': '-L' + str(deps / 'lib'),
           'LD_LIBRARY_PATH': str(deps / 'lib'), 'PKG_CONFIG_PATH': str(deps / 'lib/pkgconfig')}

    def run(command: list, cwd=work):
        command = list(map(str, command))
        commands.append([p.replace(str(work), '/build') for p in command])
        with (work / 'build.log').open('a') as log:
            subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=900)

    run(['cmake', '-S', roots['libvncclient'], '-B', work / 'vnc-build',
         '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=' + str(deps),
         '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_SKIP_RPATH=ON',
         '-DCMAKE_C_FLAGS=' + env['CFLAGS'], *['-DWITH_' + name + '=OFF' for name in VNC_OFF]])
    run(['cmake', '--build', work / 'vnc-build', '--parallel', str(args.jobs)])
    # The build installs both libraries. The distribution copies only the client.
    run(['cmake', '--install', work / 'vnc-build'])
    if rdp:
        viewer_rdp.build(run, roots['freerdp'], work, deps, env['CFLAGS'], args.jobs)
        # Current upstream headers retain deprecated callback declarations.
        env['CFLAGS'] += ' -Wno-error=deprecated-declarations'
    guac = roots['guacamole']
    if rdp:
        viewer_rdp.patches(run, guac, ROOT / 'packaging', lock.get('rdp_patches', []))
    run([guac / 'configure', '--prefix=/viewer', '--disable-static', '--disable-guacenc',
         '--disable-guaclog', '--disable-kubernetes', '--without-init-dir', '--without-systemd-dir',
         '--with-vnc', *(['--with-rdp'] if rdp else []),
         *['--without-' + name for name in GUAC_OFF if name != 'rdp' or not rdp]], cwd=guac)
    run(['make', '-j', str(args.jobs)], cwd=guac)
    run(['make', 'install', 'DESTDIR=' + str(stage)], cwd=guac)
    runtime = work / 'runtime'
    for name in ('sbin', 'lib', 'licenses', 'sources'):
        (runtime / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(stage / 'viewer/sbin/guacd', runtime / 'sbin/guacd')
    for source in (stage / 'viewer/lib').glob('*.so*'):
        shutil.copyfile(source, runtime / 'lib' / source.name)
    for source in (deps / 'lib').glob('libvncclient.so*'):
        shutil.copyfile(source, runtime / 'lib' / source.name)
    if rdp:
        for source in viewer_rdp.libraries(deps):
            shutil.copyfile(source, runtime / 'lib' / source.name)
    components = collect(runtime, args.platform_sources)
    if rdp:
        viewer_rdp.notices(roots['freerdp'], runtime / 'licenses/freerdp-SOURCE-NOTICES')
        for patch in lock['rdp_patches']:
            shutil.copyfile(ROOT / 'packaging' / patch['name'], runtime / 'sources' / patch['name'])
    for item in lock['inputs']:
        shutil.copyfile(archives[item['id']], runtime / 'sources' / item['name'])
        for name in ('LICENSE', 'NOTICE', 'COPYING'):
            source = roots[item['id']] / name
            if source.exists():
                shutil.copyfile(source, runtime / 'licenses' / (item['id'] + '-' + name))
        components.append({'type': 'library', 'name': item['id'], 'version': item['version'],
                           'licenses': [{'license': {'id': item['license']}}],
                           'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}]})
    common = {'GPL-3'}
    for notice in (runtime / 'licenses').iterdir():
        common.update(re.findall(r'/usr/share/common-licenses/([A-Za-z0-9.+_-]+)', notice.read_text()))
    for name in sorted(common):
        name = name.rstrip('.')
        shutil.copyfile(Path('/usr/share/common-licenses') / name, runtime / 'licenses' / name)
    for name in ('viewer_runtime.py', 'viewer_dependencies.py', 'viewer_rdp.py', 'source_runtime.py'):
        shutil.copyfile(ROOT / 'tools' / name, runtime / 'sources' / name)
    shutil.copyfile(ROOT / 'src/ficc/native_runtime.py', runtime / 'sources/native_runtime.py')
    shutil.copyfile(ROOT / 'packaging/viewer-inputs.json', runtime / 'sources/viewer-inputs.json')
    shutil.copyfile(ROOT / 'docs/viewer-runtime.md', runtime / 'sources/BUILD.md')
    headers = subprocess.run(['pkg-config', '--path', *headers_needed],
                             capture_output=True, text=True, check=True).stdout.splitlines()
    write_json(runtime / 'sources/build.json', {'schema': 1, 'epoch': args.epoch,
               'platform': host_platform(), 'inputs': lock, 'commands': commands,
               'environment': {key: value.replace(str(work), '/build') for key, value in env.items()},
               'development_packages': [package(Path(path).resolve()) for path in headers],
               'tools': {name: subprocess.run([name, '--version'], capture_output=True, text=True,
                          check=True).stdout.splitlines()[0] for name in ('cc', 'cmake', 'make')}})
    write_json(runtime / 'sbom.cdx.json', {'bomFormat': 'CycloneDX', 'specVersion': '1.6',
               'version': 1, 'metadata': {'component': {'type': 'application', 'name': 'ficc-native-viewer',
               'version': '1.6.0', 'licenses': [{'license': {'id': 'GPL-3.0-or-later'}}]}},
               'components': components})
    (runtime / 'NOTICE').write_text(
        'FICC native viewer\n\nApache Guacamole and LibVNCClient retain their upstream licenses.\n'
        'An RDP runtime also includes FreeRDP and WinPR under Apache-2.0.\n'
        'The linked native viewer is distributed under GPL-3.0-or-later.\n'
        'This selects the later-version option in the LibVNCClient license.\n'
        'The FICC controller is a separate program and retains its Apache-2.0 license.\n'
        'The licenses directory contains the source and distribution package notices.\n'
        'The sources directory contains the corresponding source archives and build scripts.\n'
        'Use the source package control files to check distribution source checksums.\n'
        'The system provides glibc and its ELF loader. These files are not included.\n'
        'This runtime requires the exact platform tuple in viewer-runtime.json.\n'
        'File hashes check integrity. They do not authenticate the publisher.\n'
        'VNC uses a host-mediated private transport without VNC TLS.\n'
        'RDP uses an exact certificate fingerprint on the registered private transport.\n'
        'The host disables audio, clipboard, printer and drive redirection.\n')
    inventory(runtime, args.epoch, ('vnc', 'rdp') if rdp else ('vnc',))
    validate(runtime)
    return install(runtime, output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    make = commands.add_parser('build')
    for name in ('cache', 'work', 'output', 'platform-sources'):
        make.add_argument('--' + name, required=True, type=Path)
    make.add_argument('--epoch', type=int, default=1750369721)
    make.add_argument('--jobs', type=int, choices=range(1, 17), default=2)
    make.add_argument('--rdp', action='store_true', help='Include the pinned native RDP client libraries')
    put = commands.add_parser('install')
    put.add_argument('source', type=Path)
    put.add_argument('destination', type=Path)
    check = commands.add_parser('verify')
    check.add_argument('source', type=Path)
    args = parser.parse_args()
    os.umask(0o022)
    if args.command == 'build':
        print(build(args))
    elif args.command == 'install':
        print(install(args.source, args.destination))
    else:
        validate(args.source)
        print('Viewer runtime inventory and platform match')


if __name__ == '__main__':
    main()
