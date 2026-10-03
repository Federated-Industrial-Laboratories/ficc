# SPDX-License-Identifier: Apache-2.0
"""Keep revision-bound Windows endpoints without storing plaintext credentials."""

from . import module_windows_spec as spec
from .errors import Failure

TABLES = {'module_windows_endpoints': ('id', 'value')}


def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS module_windows_endpoints (id TEXT PRIMARY KEY,value TEXT NOT NULL)')


def endpoint(value):
    spec.fields(value, {'id', 'name', 'host', 'port', 'configuration', 'commands', 'certificate_sha256',
                        'trust_ref', 'credential_ref', 'vmconnect', 'enabled', 'revision', 'machine_identity', 'probe_at'})
    for key in ('id', 'trust_ref', 'credential_ref'):
        spec.identity(value[key])
    spec.text(value['name'], 128)
    if spec.host(value['host']) != value['host']:
        raise ValueError('The Windows host name is not canonical.')
    spec.integer(value['port'], 1, 65535)
    configuration = spec.text(value['configuration'], 64)
    if not configuration.isascii() or not all(char.isalnum() or char in '.-_' for char in configuration):
        raise ValueError('Invalid JEA configuration name.')
    spec.commands(value['commands'])
    spec.identity(value['certificate_sha256'], 64)
    spec.integer(value['revision'], 1, 2**53 - 2)
    if type(value['enabled']) is not bool:
        raise ValueError('Invalid Windows endpoint state.')
    if value['machine_identity'] is not None:
        spec.identity(value['machine_identity'], 64)
    if type(value['probe_at']) not in {int, float} or not 0 <= value['probe_at'] < 1e12:
        raise ValueError('Invalid Windows probe timestamp.')
    if value['enabled'] and (value['machine_identity'] is None or value['probe_at'] == 0):
        raise ValueError('An enabled Windows endpoint requires a checked identity.')
    console = value['vmconnect']
    if console is not None:
        spec.fields(console, {'port', 'certificate_sha256', 'credential_ref'})
        spec.integer(console['port'], 1, 65535)
        spec.identity(console['certificate_sha256'], 64)
        spec.identity(console['credential_ref'])
    spec.encode(value)
    return value


def validate_records(db):
    rows = db.execute('SELECT id,value FROM module_windows_endpoints ORDER BY id').fetchall()
    if len(rows) > 64:
        raise ValueError('The Windows endpoint capacity is exceeded.')
    ids: set[str] = set()
    refs: set[str] = set()
    for row in rows:
        value = endpoint(spec.decode(row[1].encode()))
        if row[0] != value['id'] or row[0] in ids:
            raise ValueError('The Windows endpoint row identity differs.')
        ids.add(row[0])
        selected = [value['trust_ref'], value['credential_ref']]
        if value['vmconnect']:
            selected.append(value['vmconnect']['credential_ref'])
        if len(set(selected)) != len(selected) or set(selected) & refs:
            raise ValueError('Windows endpoints require separate private credential records.')
        refs.update(selected)


def disable_restored(db):
    validate_records(db)
    for identity, raw in db.execute('SELECT id,value FROM module_windows_endpoints').fetchall():
        value = spec.decode(raw.encode())
        value.update(enabled=False, revision=value['revision'] + 1)
        endpoint(value)
        db.execute('UPDATE module_windows_endpoints SET value=:p0 WHERE id=:p1', (spec.encode(value).decode(), identity))


class Records:
    def __init__(self, store):
        self.store = store

    def all(self):
        with self.store.lock:
            return [endpoint(spec.decode(row[0].encode())) for row in
                    self.store.db.execute('SELECT value FROM module_windows_endpoints ORDER BY id')]

    def get(self, identity):
        spec.identity(identity)
        with self.store.lock:
            row = self.store.db.execute('SELECT value FROM module_windows_endpoints WHERE id=:p0', (identity,)).fetchone()
        if row is None:
            raise Failure('windows_endpoint_missing', 'The registered Windows endpoint was not found.', 404)
        return endpoint(spec.decode(row[0].encode()))

    def save(self, value, expected_revision=None):
        endpoint(value)
        if expected_revision is not None:
            spec.integer(expected_revision, 1, 2**53 - 2)
        with self.store.lock, self.store.db:
            row = self.store.db.execute('SELECT value FROM module_windows_endpoints WHERE id=:p0', (value['id'],)).fetchone()
            if row is None:
                if expected_revision is not None or value['revision'] != 1:
                    raise Failure('windows_endpoint_changed', 'The Windows endpoint revision changed.', 409)
                if self.store.db.execute('SELECT count(*) FROM module_windows_endpoints').fetchone()[0] >= 64:
                    raise Failure('capacity', 'The Windows endpoint limit was reached.', 409)
                self.store.db.execute('INSERT INTO module_windows_endpoints VALUES (:p0,:p1)',
                                      (value['id'], spec.encode(value).decode()))
            else:
                prior = endpoint(spec.decode(row[0].encode()))
                if prior['revision'] != expected_revision or value['revision'] != expected_revision + 1:
                    raise Failure('windows_endpoint_changed', 'The Windows endpoint revision changed.', 409)
                self.store.db.execute('UPDATE module_windows_endpoints SET value=:p0 WHERE id=:p1',
                                      (spec.encode(value).decode(), value['id']))

    def remove(self, identity, expected_revision):
        spec.integer(expected_revision, 1, 2**53 - 2)
        with self.store.lock, self.store.db:
            value = self.get(identity)
            if value['revision'] != expected_revision:
                raise Failure('windows_endpoint_changed', 'The Windows endpoint revision changed.', 409)
            from .resource_store import Resources
            Resources(self.store).remove('nodes', identity)
            self.store.db.execute('DELETE FROM module_windows_endpoints WHERE id=:p0', (identity,))
