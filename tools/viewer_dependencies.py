# SPDX-License-Identifier: Apache-2.0
"""Copy declared ELF dependencies with their package notices and source files."""

import email
import hashlib
import re
import shutil
import subprocess
from pathlib import Path

PLATFORM = {'libc.so.6', 'libm.so.6', 'libdl.so.2', 'libpthread.so.0', 'librt.so.1',
            'ld-linux-x86-64.so.2', 'libresolv.so.2'}


def command(args: list[str]) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=30).stdout


def needed(path: Path) -> list[str]:
    data = command(['readelf', '-d', str(path)])
    if re.search(r'\((?:RPATH|RUNPATH)\).*\[(?!/viewer/lib\])', data):
        raise ValueError('ELF runtime path must be absent or /viewer/lib')
    return re.findall(r'\(NEEDED\).*\[([A-Za-z0-9_.+-]+)\]', data)


def source_index(directory: Path) -> dict[tuple[str, str], tuple[Path, list[Path]]]:
    result = {}
    for path in sorted(directory.glob('*.dsc')):
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise ValueError('Invalid source control file')
        text = path.read_text()
        if text.startswith('-----BEGIN PGP SIGNED MESSAGE-----'):
            text = text.split('\n\n', 1)[1].split('-----BEGIN PGP SIGNATURE-----')[0]
        fields = email.message_from_string(text)
        key = (fields.get('Source'), fields.get('Version'))
        if not all(key) or key in result:
            raise ValueError('Invalid or duplicate source package')
        files = []
        for row in fields.get('Checksums-Sha256', '').splitlines():
            if not row.strip():
                continue
            digest, size, name = row.split()
            if (not re.fullmatch('[A-Za-z0-9_.+~-]+', name) or not size.isdecimal()
                    or not re.fullmatch('[0-9a-f]{64}', digest)):
                raise ValueError('Invalid source member')
            member = directory / name
            if (member.is_symlink() or not member.is_file() or member.stat().st_size != int(size)
                    or int(size) > 128 * 1024 * 1024
                    or hashlib.sha256(member.read_bytes()).hexdigest() != digest):
                raise ValueError('Source file differs from its source control checksum')
            files.append(member)
        if not files:
            raise ValueError('Source package has no SHA-256 inventory')
        result[key] = (path, files)
    return result


def package(path: Path) -> tuple[str, str, str, str]:
    # Both merged and separate /usr layouts occur in supported build hosts.
    names = [str(path), str(path).removeprefix('/usr')]
    found = None
    for name in names:
        query = subprocess.run(['dpkg-query', '-S', name], text=True, capture_output=True, timeout=10)
        if query.returncode == 0:
            found = query.stdout.split(': ', 1)[0]
            break
    if found is None or '\n' in found:
        raise ValueError('ELF dependency has no unique installed package')
    fields = command(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}', found])
    values = fields.split('\t')
    if len(values) != 4 or any(not re.fullmatch('[A-Za-z0-9.+:~_-]+', value) for value in values):
        raise ValueError('Invalid dependency package identity')
    # Refuse modified package files. dpkg checks its installed checksum inventory.
    if command(['dpkg', '--verify', found]).strip():
        raise ValueError('Installed dependency differs from its package: ' + found)
    return tuple(values)


def collect(runtime: Path, sources: Path) -> list[dict]:
    index = source_index(sources)
    libraries = runtime / 'lib'
    lookup = {}
    for line in command(['/sbin/ldconfig', '-p']).splitlines():
        match = re.fullmatch(r'\s*(\S+) \(libc6,x86-64[^)]*\) => (\S+)', line)
        if match:
            lookup.setdefault(match[1], Path(match[2]).resolve())
    queue = [runtime / 'sbin/guacd', *libraries.iterdir()]
    processed, packages, copied_sources = set(), {}, set()
    while queue:
        path = queue.pop()
        if path.name in processed:
            continue
        processed.add(path.name)
        for name in needed(path):
            if name in PLATFORM:
                continue
            target = libraries / name
            if not target.exists():
                source = lookup.get(name)
                if source is None:
                    raise ValueError('ELF dependency is absent: ' + name)
                binary, version, source_name, source_version = package(source)
                if binary not in packages:
                    source_entry = index.get((source_name, source_version))
                    if source_entry is None:
                        raise ValueError('Add the exact source package: ' + source_name + '=' + source_version)
                    notice = Path('/usr/share/doc') / binary.split(':')[0] / 'copyright'
                    if not notice.is_file() or notice.stat().st_size > 2 * 1024 * 1024:
                        raise ValueError('Package copyright file is absent')
                    notice_target = runtime / 'licenses' / (binary + '.copyright')
                    shutil.copyfile(notice, notice_target)
                    for member in (source_entry[0], *source_entry[1]):
                        if member.name not in copied_sources:
                            shutil.copyfile(member, runtime / 'sources' / member.name)
                            copied_sources.add(member.name)
                    packages[binary] = {'type': 'library', 'name': binary, 'version': version,
                                        'properties': [{'name': 'ficc:source-package', 'value': source_name},
                                                       {'name': 'ficc:source-version', 'value': source_version},
                                                       {'name': 'ficc:notice', 'value': 'licenses/' + notice_target.name}]}
                shutil.copyfile(source, target)
            queue.append(target)
    return list(packages.values())
