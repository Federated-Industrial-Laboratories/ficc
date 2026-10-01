#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Build or install a private Windows transport. Inputs: pinned files; exit: zero on success.
"""Package the maintained Windows transport separately from the controller ABI."""

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from release_lib.notices import member
from release_lib.payload import python_notices, repair_records
from release_lib.runtimes import WINDOWS_HELPERS
from source_runtime import download, secure_dir, unpack

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ficc.native_runtime import checksum, host_platform  # noqa: E402
from ficc.windows_runtime import MANIFEST, validate  # noqa: E402


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def install(source, destination):
    validate(source)
    parent = secure_dir(destination.absolute().parent)
    if destination.exists() or destination.is_symlink():
        raise ValueError('The Windows runtime destination must be new.')
    stage = Path(tempfile.mkdtemp(prefix='.windows-', dir=parent))
    try:
        shutil.copytree(source, stage / 'runtime', symlinks=True)
        validate(stage / 'runtime')
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(stage / 'runtime'), -100, os.fsencode(destination), 1) != 0:
            raise OSError(ctypes.get_errno(), 'Cannot replace a Windows runtime destination.')
    finally:
        shutil.rmtree(stage)
    return destination


def build(args):
    if args.work.exists() or args.output.exists():
        raise ValueError('The Windows work and output directories must be new.')
    work = secure_dir(args.work)
    cache = secure_dir(args.cache)
    output = args.output.absolute()
    secure_dir(output.parent)
    if work == output or work.is_relative_to(output) or output.is_relative_to(work):
        raise ValueError('Windows work and output directories must be separate.')
    lock = json.loads((ROOT / 'packaging/windows-inputs.json').read_text())
    archives = {item['id']: download(item, cache) for item in lock['inputs']}
    unpack(archives['python'], work / 'extract')
    runtime = work / 'runtime'
    runtime.mkdir(mode=0o700)
    shutil.copytree(work / 'extract/python', runtime / 'python', symlinks=False)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'LANG': 'C', 'PYTHONHASHSEED': '0',
           'SOURCE_DATE_EPOCH': str(args.epoch), 'PIP_CONFIG_FILE': '/dev/null'}
    subprocess.run([runtime / 'python/bin/python3', '-I', '-m', 'pip', 'install', '--no-index',
                    '--no-deps', '--no-compile', '--disable-pip-version-check',
                    *[path for path in archives.values() if path.suffix == '.whl']],
                   env=env, check=True, timeout=120, stdout=subprocess.DEVNULL)
    for path in runtime.rglob('__pycache__'):
        shutil.rmtree(path)
    site = runtime / 'python/lib/python3.12/site-packages'
    for path in site.glob('pip*'):
        if path.is_dir():
            shutil.rmtree(path)
    for path in (runtime / 'python/bin').iterdir():
        if path.name != 'python3':
            path.unlink()
    for path in site.glob('*.dist-info/direct_url.json'):
        path.unlink()
    repair_records(site, runtime)
    helper = runtime / 'helper/ficc'
    helper.mkdir(parents=True)
    (helper / '__init__.py').write_text('# SPDX-License-Identifier: Apache-2.0\n')
    for name in WINDOWS_HELPERS:
        shutil.copyfile(ROOT / 'src/ficc' / name, helper / name)
    (runtime / 'helper/entry.py').write_text(
        '# SPDX-License-Identifier: Apache-2.0\nimport sys\nfrom pathlib import Path\n'
        'sys.path.insert(0, str(Path(__file__).resolve().parent))\n'
        'from ficc.windows_helper import main\nraise SystemExit(main())\n')
    sources = runtime / 'sources'
    sources.mkdir()
    write(sources / 'inputs.json', lock)
    for file in (Path(__file__), ROOT / 'tools/source_runtime.py', ROOT / 'src/ficc/windows_runtime.py'):
        shutil.copyfile(file, sources / ('_'.join(file.relative_to(ROOT).parts)))
    for file in (ROOT / 'tools/release_lib').glob('*.py'):
        shutil.copyfile(file, sources / ('release_lib_' + file.name))
    for item in lock['inputs']:
        if item['id'].endswith('-source'):
            shutil.copyfile(archives[item['id']], sources / item['name'])
    licenses = runtime / 'licenses'
    licenses.mkdir()
    python_notices(archives['python-metadata'], licenses / 'python')
    (licenses / 'python/LICENSE.liblzma.txt').write_bytes(member(archives['python-build-source'], 'LICENSE.liblzma.txt'))
    shutil.copyfile(archives['zlib-ng-license'], licenses / 'python/LICENSE.zlib-ng.txt')
    shutil.copyfile(ROOT / 'LICENSE', licenses / 'FICC-LICENSE')
    for path in (runtime / 'python').rglob('*'):
        if path.is_file() and ('license' in path.name.lower() or 'copying' in path.name.lower()):
            name = str(path.relative_to(runtime / 'python')).replace('/', '_')
            shutil.copyfile(path, licenses / name)
    (runtime / 'NOTICE').write_text(
        'FICC Windows transport runtime\n\n'
        'This optional runtime requires its recorded Linux build platform.\n'
        'The controller retains its separate supported platform baseline.\n'
        'The inventory checks local files. It does not authenticate a publisher.\n'
        'Pinned inputs and source links are in sources/inputs.json.\n'
        'Dependency source and license files are retained in python and licenses.\n')
    write(runtime / 'sbom.cdx.json', {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'components': [{'type': 'library', 'name': item['id'], 'version': item.get('version', '3.12.14'),
                        'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}],
                        'externalReferences': [{'type': 'distribution', 'url': item['url']}]} for item in lock['inputs']]})
    files = {}
    for path in sorted(runtime.rglob('*')):
        if path.is_dir():
            path.chmod(0o755)
        if path.is_file():
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            path.chmod(mode)
            os.utime(path, (args.epoch, args.epoch))
            files[path.relative_to(runtime).as_posix()] = {'mode': mode, 'size': path.stat().st_size,
                                                         'sha256': checksum(path)}
    write(runtime / MANIFEST, {'schema': 1, 'platform': host_platform(), 'files': files})
    (runtime / MANIFEST).chmod(0o644)
    validate(runtime)
    return install(runtime, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    make = sub.add_parser('build')
    for name in ('work', 'output', 'cache'):
        make.add_argument('--' + name, type=Path, required=True)
    make.add_argument('--epoch', type=int, default=1790553600)
    add = sub.add_parser('install')
    add.add_argument('--source', type=Path, required=True)
    add.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    print(build(args) if args.action == 'build' else install(args.source, args.destination))


if __name__ == '__main__':
    main()
