#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Install a source checkout per user. Inputs: options and pinned tools; exit: 0 on success.
"""Build this checkout and install a private runtime, command and desktop launcher."""

import argparse
import fcntl
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from source_runtime import download, secure_dir, unpack

MARKER = '#!/bin/sh\n# FICC source installation\n'
ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    print('+ ' + shlex.join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), check=True, **kwargs)


def check_wrapper(path: Path) -> None:
    if path.is_symlink() or (path.exists() and (
            not path.is_file() or path.stat().st_uid != os.getuid()
            or not path.read_text().startswith(MARKER))):
        raise ValueError('Refusing to replace an existing command: ' + str(path))


def source_copy(destination: Path) -> None:
    destination.mkdir()
    for name in ('pyproject.toml', 'README.md', 'LICENSE', 'NOTICE', 'MANIFEST.in',
                 'requirements.lock', 'requirements-build.lock'):
        shutil.copyfile(ROOT / name, destination / name)

    def ignored(directory, names):
        skip = {n for n in names if n in {'__pycache__', 'node_modules', 'static'}
                or n.endswith('.egg-info')}
        for name in set(names) - skip:
            if (Path(directory) / name).is_symlink():
                raise ValueError('Source links are unsupported')
        return skip

    for name in ('src', 'node'):
        shutil.copytree(ROOT / name, destination / name, ignore=ignored)
    web = destination / 'web'
    web.mkdir()
    for name in ('package.json', 'package-lock.json', 'build.mjs'):
        shutil.copyfile(ROOT / 'web' / name, web / name)
    shutil.copytree(ROOT / 'web/static', web / 'static', ignore=ignored)


def install(args) -> Path:
    if os.getuid() == 0:
        raise ValueError('Run ./install.sh as the desktop account, without sudo')
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('The source installer supports Linux x86_64')
    if sys.version_info < (3, 10) or not hasattr(__import__('tarfile'), 'data_filter'):
        raise ValueError('Use an updated system Python 3.10 or later')
    required = ['ssh', 'timeout'] + ([] if args.no_desktop else ['systemctl', 'xdg-open'])
    if any(shutil.which(name) is None for name in required):
        raise ValueError('Install OpenSSH client, coreutils, systemd and xdg-utils; see docs/install.md')
    data = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share')))
    base = secure_dir(data / 'ficc/source-installs')
    cache = secure_dir(Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache'))) / 'ficc/installer')
    command = secure_dir(Path.home() / '.local/bin') / 'ficc'
    fd = os.open(base / 'install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_wrapper(command)
        if not args.no_desktop:
            run(['systemctl', '--user', 'show-environment'], stdout=subprocess.DEVNULL)
        target = Path(tempfile.mkdtemp(prefix='runtime-', dir=base))
        activating = False
        try:
            python_input = next(i for i in json.loads((ROOT / 'packaging/inputs.json').read_text())['inputs']
                                if i['id'] == 'python')
            unpack(download(python_input, cache), target / 'runtime')
            python = target / 'runtime/python/bin/python3'
            run([python, '-m', 'venv', target / 'venv'])
            python = target / 'venv/bin/python'
            with tempfile.TemporaryDirectory(prefix='build-', dir=base) as work_name:
                work = Path(work_name)
                node_input = json.loads((ROOT / 'tools/source-inputs.json').read_text())['node']
                unpack(download(node_input, cache), work / 'node')
                node_bin = work / 'node' / node_input['name'].removesuffix('.tar.xz') / 'bin'
                env = {**os.environ, 'PATH': str(node_bin) + os.pathsep + os.environ.get('PATH', ''),
                       'PYTHONNOUSERSITE': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}
                source = work / 'source'
                source_copy(source)
                for filename in ('requirements-build.lock', 'requirements.lock'):
                    run([python, '-m', 'pip', 'install', '--require-hashes', '-r', source / filename], env=env)
                run([node_bin / 'npm', 'ci', '--ignore-scripts', '--prefix', source / 'web'], env=env)
                run([node_bin / 'npm', 'run', 'build', '--prefix', source / 'web'], env=env)
                run([python, '-m', 'build', '--wheel', '--no-isolation', source], env=env)
                wheels = list((source / 'dist').glob('*.whl'))
                if len(wheels) != 1:
                    raise ValueError('Build must produce exactly one wheel')
                run([python, '-m', 'pip', 'install', '--no-deps', wheels[0]], env=env)
            executable = target / 'venv/bin/ficc'
            run([executable, '--version'])
            # Retain the runtime if launcher installation partially writes its configuration.
            activating = True
            if not args.no_desktop:
                run([python, ROOT / 'tools/source_launcher.py', *args.profile])
            check_wrapper(command)
            text = MARKER + 'exec ' + shlex.quote(str(executable)) + ' "$@"\n'
            temporary = command.with_name('.ficc-install-' + target.name)
            with temporary.open('x') as stream:
                stream.write(text)
            temporary.chmod(0o755)
            os.replace(temporary, command)
            (target / 'installation.json').write_text(json.dumps({'command': str(command), 'source': str(ROOT)}) + '\n')
            print('\nInstalled: ' + str(command))
            print('Start: ' + str(command) + ' desktop')
            if str(command.parent) not in os.environ.get('PATH', '').split(os.pathsep):
                print('For this terminal: export PATH="$HOME/.local/bin:$PATH"')
            print('Then use: ficc desktop  |  ficc status  |  ficc stop')
            return command
        except BaseException:
            if not activating:
                shutil.rmtree(target)
            else:
                print('Retained runtime after activation failure: ' + str(target), file=sys.stderr)
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', action='append', default=[], help='Approve a trusted SSH alias on first installation')
    parser.add_argument('--no-desktop', action='store_true', help='Install command only; use serve/open without systemd')
    args = parser.parse_args()
    if args.no_desktop and args.profile:
        parser.error('--profile requires desktop installation; use serve --profile for command-only operation')
    os.umask(0o077)
    try:
        install(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print('FICC installation failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
