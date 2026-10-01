#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare an owned VirtualBox IPC socket or one stopped VM for FICC."""

import argparse
import getpass
import json
import os
import re
import socket
import stat
import struct
import subprocess
from pathlib import Path


def command(*args):
    result = subprocess.run(['VBoxManage', *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError('VirtualBox refused the requested setup operation.')
    return result.stdout


def private(path):
    info = path.lstat()
    if path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('The selected directory must be private, owned and without links.')


def transport():
    location = Path('/tmp') / ('.vbox-' + getpass.getuser() + '-ipc') / 'ipcd'
    private(location.parent)
    info = location.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('The provider socket must be owned by this account.')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(2)
        stream.connect(str(location))
        pid, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.getuid() or Path('/proc', str(pid), 'exe').resolve() != Path('/usr/lib/virtualbox/VBoxSVC'):
            raise ValueError('The local socket does not belong to the expected provider process.')
    current = location.lstat()
    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
        raise ValueError('The provider socket changed during setup.')
    location.chmod(0o600)
    print(json.dumps({'socket_path': str(location), 'owner_uid': uid, 'pid': pid}))


def machine(identifier):
    if re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}', identifier) is None:
        raise ValueError('Select the exact registered VM UUID.')
    # The provider output can contain a credential. Retain only selected fields.
    values = {}
    for line in command('showvminfo', identifier, '--machinereadable').splitlines():
        key, _, value = line.partition('=')
        if key in {'UUID', 'VMState', 'CfgFile'}:
            values[key] = json.loads(value)
    if values.get('UUID') != identifier or values.get('VMState') != 'poweroff':
        raise ValueError('The exact selected VM must be powered off before setup.')
    private(Path(values['CfgFile']).parent)
    packs = command('list', 'extpacks')
    if not re.search(r'^Pack no\. \d+:\s+FICC VNC$', packs, re.MULTILINE):
        raise ValueError('Install the FICC VNC extension before display setup.')
    directory = Path.home() / '.local/run/ficc-displays'
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    private(directory)
    path = str(directory / (identifier + '.sock'))
    if len(os.fsencode(path)) > 107:
        raise ValueError('The private display socket path exceeds the Unix path limit.')
    # The C API creates and stores the credential inside the setup process.
    # Only the public VM identity and socket path enter the process arguments.
    program = Path(__file__).with_name('program').resolve(strict=True)
    result = subprocess.run(['/lib64/ld-linux-x86-64.so.2', str(program), '--prepare-vm', identifier, path, '--confirm'],
        capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('The provider refused the stopped VM setup. No credential is returned.')
    print(json.dumps({'vm_id': identifier, 'display': 'private-unix', 'socket_path': path, 'identity_ready': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('transport', 'vm'))
    parser.add_argument('--vm')
    parser.add_argument('--confirm', action='store_true')
    args = parser.parse_args()
    if not args.confirm:
        parser.error('Read the setup guide, then pass --confirm to change the selected provider resource.')
    if command('--version').strip() != '7.2.20r175154':
        raise ValueError('This setup requires VirtualBox 7.2.20 revision 175154.')
    if args.action == 'transport':
        if args.vm:
            parser.error('Transport setup does not select a VM.')
        transport()
    elif args.vm:
        machine(args.vm)
    else:
        parser.error('VM setup requires --vm with its exact UUID.')


if __name__ == '__main__':
    main()
