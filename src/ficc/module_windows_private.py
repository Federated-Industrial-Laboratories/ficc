# SPDX-License-Identifier: Apache-2.0
"""Keep endpoint trust and account secrets in private files outside backups."""

import os
import secrets
import ssl
import stat
from pathlib import Path

from . import module_windows_spec as spec
from .native_runtime import safe_directory
from .settings import private_directory


def credentials(value):
    spec.fields(value, {'username', 'password', 'domain'})
    spec.text(value['username'], 128)
    spec.text(value['password'], 256)
    spec.text(value['domain'], 253, 0)
    return value


def trust(value):
    if (not isinstance(value, str) or not 1 <= len(value.encode()) <= 65536
            or 'PRIVATE KEY' in value or '-----BEGIN CERTIFICATE-----' not in value):
        raise ValueError('Supply a PEM certificate trust chain.')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=value)
    return value


class Private:
    def __init__(self, state):
        self.path = Path(state) / 'windows-private'
        private_directory(self.path)
        safe_directory(self.path)

    def write(self, kind, value):
        if kind == 'credentials':
            credentials(value)
        elif kind == 'trust':
            trust(value)
        else:
            raise ValueError('Invalid Windows private record type.')
        reference = secrets.token_hex(16)
        data = spec.encode({'kind': kind, 'value': value})
        directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(reference, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)
        return reference

    def read(self, reference, kind):
        spec.identity(reference)
        safe_directory(self.path)
        fd = os.open(self.path / reference, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 131072):
                raise ValueError('Windows private record is not a private regular file.')
            record = spec.decode(stream.read(131073))
        spec.fields(record, {'kind', 'value'})
        if record['kind'] != kind:
            raise ValueError('Windows private record type differs.')
        return credentials(record['value']) if kind == 'credentials' else trust(record['value'])

    def ready(self, reference, kind):
        try:
            self.read(reference, kind)
            return True
        except (OSError, ValueError, ssl.SSLError):
            return False

    def remove(self, reference):
        spec.identity(reference)
        safe_directory(self.path)
        try:
            (self.path / reference).unlink()
        except FileNotFoundError:
            return
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
